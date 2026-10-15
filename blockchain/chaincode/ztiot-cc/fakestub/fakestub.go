// Package fakestub runs the smart contract in memory, without a Fabric
// network, for unit tests and for the local mock ledger.
//
// It wraps the official shimtest.MockStub and adds the three things the
// mock leaves out: history (GetHistoryForKey), CouchDB-style queries
// (GetQueryResult, simple subset) and caller identities with roles.
// Every call goes through the real contractapi.Invoke, so identity checks
// and response schema validation run exactly as they do on a peer.
package fakestub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/golang/protobuf/proto"
)

// Stub is an in-memory ledger.
type Stub struct {
	*shimtest.MockStub
	mu      sync.Mutex
	args    []string
	history map[string][]*queryresult.KeyModification
	clock   time.Time
	txCount int
	// LastTxID is the ID of the most recent transaction, kept after it ends.
	LastTxID string
	// LastEvent is the event set by the most recent transaction. A peer
	// also keeps only one event per transaction (the last SetEvent wins).
	LastEvent string
}

// New creates an empty ledger for the given chaincode.
func New(name string, cc shim.Chaincode) *Stub {
	return &Stub{
		MockStub: shimtest.NewMockStub(name, cc),
		history:  map[string][]*queryresult.KeyModification{},
		clock:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// Invoke runs one transaction as the given caller and returns the response.
// Each transaction is one second after the previous one, so tests are
// deterministic.
func (s *Stub) Invoke(cc shim.Chaincode, caller []byte, fn string, args ...string) peer.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txCount++
	txid := fmt.Sprintf("tx%06d", s.txCount)
	s.args = append([]string{fn}, args...)
	s.Creator = caller
	s.MockTransactionStart(txid)
	s.clock = s.clock.Add(time.Second)
	s.TxTimestamp = &timestamp.Timestamp{Seconds: s.clock.Unix(), Nanos: int32(s.clock.Nanosecond())}
	resp := cc.Invoke(s)
	s.MockTransactionEnd(txid)
	s.LastTxID = txid
	return resp
}

// Advance moves the fake clock forward, for window-based tests.
func (s *Stub) Advance(d time.Duration) { s.mu.Lock(); s.clock = s.clock.Add(d); s.mu.Unlock() }

// ---- argument handling (contractapi reads these) ----------------------

func (s *Stub) GetFunctionAndParameters() (string, []string) {
	if len(s.args) == 0 {
		return "", nil
	}
	return s.args[0], s.args[1:]
}

func (s *Stub) GetStringArgs() []string { return s.args }

func (s *Stub) GetArgs() [][]byte {
	out := make([][]byte, len(s.args))
	for i, a := range s.args {
		out[i] = []byte(a)
	}
	return out
}

// SetEvent records the event name. shimtest.MockStub sends events into a
// channel with room for 100 and then blocks for ever, which hangs any
// long-running use such as the mock ledger.
func (s *Stub) SetEvent(name string, payload []byte) error {
	if name == "" {
		return fmt.Errorf("event name can not be empty")
	}
	s.LastEvent = name
	return nil
}

// ---- writes are recorded so history works -----------------------------

func (s *Stub) record(key string, value []byte, del bool) {
	s.history[key] = append(s.history[key], &queryresult.KeyModification{
		TxId: s.TxID, Value: value, IsDelete: del,
		Timestamp: &timestamp.Timestamp{Seconds: s.TxTimestamp.Seconds, Nanos: s.TxTimestamp.Nanos},
	})
}

func (s *Stub) PutState(key string, value []byte) error {
	if err := s.MockStub.PutState(key, value); err != nil {
		return err
	}
	s.record(key, value, false)
	return nil
}

func (s *Stub) DelState(key string) error {
	if err := s.MockStub.DelState(key); err != nil {
		return err
	}
	s.record(key, nil, true)
	return nil
}

// GetHistoryForKey returns modifications newest first, like a peer.
func (s *Stub) GetHistoryForKey(key string) (shim.HistoryQueryIteratorInterface, error) {
	mods := s.history[key]
	rev := make([]*queryresult.KeyModification, len(mods))
	for i, m := range mods {
		rev[len(mods)-1-i] = m
	}
	return &histIter{items: rev}, nil
}

type histIter struct {
	items []*queryresult.KeyModification
	i     int
}

func (h *histIter) HasNext() bool { return h.i < len(h.items) }
func (h *histIter) Close() error  { return nil }
func (h *histIter) Next() (*queryresult.KeyModification, error) {
	if !h.HasNext() {
		return nil, fmt.Errorf("no more items")
	}
	h.i++
	return h.items[h.i-1], nil
}

// ---- a small subset of CouchDB selectors ------------------------------
// Supports {"selector": {"field": value, "field": {"$gte": v, "$lte": v,
// "$gt": v, "$lt": v, "$eq": v}}}. Enough to test the phase 3 query.

func (s *Stub) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	var q struct {
		Selector map[string]interface{} `json:"selector"`
	}
	if err := json.Unmarshal([]byte(query), &q); err != nil {
		return nil, fmt.Errorf("bad query: %w", err)
	}
	keys := make([]string, 0, len(s.State))
	for k := range s.State {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*queryresult.KV
	for _, k := range keys {
		var doc map[string]interface{}
		if json.Unmarshal(s.State[k], &doc) != nil {
			continue
		}
		if matches(doc, q.Selector) {
			out = append(out, &queryresult.KV{Key: k, Value: s.State[k]})
		}
	}
	return &kvIter{items: out}, nil
}

func matches(doc, sel map[string]interface{}) bool {
	for field, cond := range sel {
		val, ok := doc[field]
		if !ok {
			return false
		}
		if ops, isOps := cond.(map[string]interface{}); isOps {
			for op, want := range ops {
				c, comparable := compare(val, want)
				if !comparable {
					return false
				}
				switch op {
				case "$eq":
					if c != 0 {
						return false
					}
				case "$gt":
					if c <= 0 {
						return false
					}
				case "$gte":
					if c < 0 {
						return false
					}
				case "$lt":
					if c >= 0 {
						return false
					}
				case "$lte":
					if c > 0 {
						return false
					}
				default:
					return false
				}
			}
		} else if c, ok := compare(val, cond); !ok || c != 0 {
			return false
		}
	}
	return true
}

func compare(a, b interface{}) (int, bool) {
	switch av := a.(type) {
	case float64:
		bv, ok := b.(float64)
		if !ok {
			return 0, false
		}
		switch {
		case av < bv:
			return -1, true
		case av > bv:
			return 1, true
		}
		return 0, true
	case string:
		bv, ok := b.(string)
		if !ok {
			return 0, false
		}
		return strings.Compare(av, bv), true
	case bool:
		bv, ok := b.(bool)
		return 0, ok && av == bv
	}
	return 0, false
}

type kvIter struct {
	items []*queryresult.KV
	i     int
}

func (k *kvIter) HasNext() bool { return k.i < len(k.items) }
func (k *kvIter) Close() error  { return nil }
func (k *kvIter) Next() (*queryresult.KV, error) {
	if !k.HasNext() {
		return nil, fmt.Errorf("no more items")
	}
	k.i++
	return k.items[k.i-1], nil
}

// ---- caller identities ------------------------------------------------

// attrOID is the certificate extension Fabric CA uses for attributes.
var attrOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}

// Identity builds a serialized Fabric identity: an X.509 certificate with
// the given OU and, optionally, a "role" attribute, exactly as Fabric CA
// would issue them.
func Identity(mspID, commonName, ou, role string) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName, OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if role != "" {
		val, _ := json.Marshal(map[string]map[string]string{"attrs": {"role": role}})
		tmpl.ExtraExtensions = []pkix.Extension{{Id: attrOID, Value: val}}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sid := &msp.SerializedIdentity{Mspid: mspID, IdBytes: certPEM}
	b, _ := proto.Marshal(sid)
	return b
}
