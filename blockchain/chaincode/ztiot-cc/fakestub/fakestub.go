package fakestub

import (
	"crypto/ecdsa"     // make a key pair for test certificates
	"crypto/elliptic"  // P-256 curve (the curve Fabric uses)
	"crypto/rand"      // secure random numbers
	"crypto/x509"      // build X.509 certificates
	"crypto/x509/pkix" // certificate subject (name, OU) and extensions
	"encoding/asn1"    // object identifier (OID) for the attribute extension
	"encoding/json"    // JSON for attributes and query documents
	"encoding/pem"     // "-----BEGIN CERTIFICATE-----" text format
	"fmt"              // errors and transaction IDs
	"math/big"         // certificate serial number
	"sort"             // sort keys so query results are in a fixed order
	"strings"          // compare text values
	"sync"             // mutex: one transaction at a time
	"time"             // fake clock

	"github.com/golang/protobuf/proto"                           // encode the identity like Fabric does
	"github.com/golang/protobuf/ptypes/timestamp"                // transaction timestamp type
	"github.com/hyperledger/fabric-chaincode-go/shim"            // the stub interface the contract uses
	"github.com/hyperledger/fabric-chaincode-go/shimtest"        // official in-memory mock stub
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult" // KV and KeyModification types
	"github.com/hyperledger/fabric-protos-go/msp"                // SerializedIdentity (MSP ID + certificate)
	"github.com/hyperledger/fabric-protos-go/peer"               // Response type (Status, Message, Payload)
)

// Stub is an in-memory ledger.
type Stub struct {
	*shimtest.MockStub
	mu      sync.Mutex                                // lock so two requests never run at the same time
	args    []string                                  // function name + arguments of the current transaction
	history map[string][]*queryresult.KeyModification // every write to every key, oldest first
	clock   time.Time                                 // fake time, moves 1 second per transaction
	txCount int                                       // number of transactions so far
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
		clock:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), // fixed start time, so results are the same every run
	}
}

// Invoke runs one transaction as the given caller and returns the response.
// Each transaction is one second after the previous one, so tests are
// deterministic.
func (s *Stub) Invoke(cc shim.Chaincode, caller []byte, fn string, args ...string) peer.Response {
	s.mu.Lock()         // the mock ledger server may get requests at the same time
	defer s.mu.Unlock() // unlock when the function ends
	s.txCount++
	txid := fmt.Sprintf("tx%06d", s.txCount) // tx000001, tx000002, ...
	s.args = append([]string{fn}, args...)
	s.Creator = caller // the certificate the contract will read for access control
	s.MockTransactionStart(txid)
	s.clock = s.clock.Add(time.Second)
	s.TxTimestamp = &timestamp.Timestamp{Seconds: s.clock.Unix(), Nanos: int32(s.clock.Nanosecond())}
	resp := cc.Invoke(s) // run the real contract code through contractapi
	s.MockTransactionEnd(txid)
	s.LastTxID = txid
	return resp // Status 200 = success, otherwise Message has the error
}

// Advance moves the fake clock forward, for window-based tests.
func (s *Stub) Advance(d time.Duration) { s.mu.Lock(); s.clock = s.clock.Add(d); s.mu.Unlock() }

// argument handling (contractapi reads these)

func (s *Stub) GetFunctionAndParameters() (string, []string) {
	if len(s.args) == 0 {
		return "", nil
	}
	return s.args[0], s.args[1:] // first = function name, rest = arguments
}

func (s *Stub) GetStringArgs() []string { return s.args }

// GetArgs returns the same values as bytes (Fabric passes arguments as bytes).
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
		return fmt.Errorf("event name can not be empty") // same rule as a real peer
	}
	s.LastEvent = name
	return nil
}

// writes are recorded so history works
// The official mock has no history database. Every PutState and DelState
// below is also saved in s.history, so GetHistoryForKey can return it.

// record saves one change of a key: transaction ID, new value, delete or not, time.
func (s *Stub) record(key string, value []byte, del bool) {
	s.history[key] = append(s.history[key], &queryresult.KeyModification{
		TxId: s.TxID, Value: value, IsDelete: del,
		Timestamp: &timestamp.Timestamp{Seconds: s.TxTimestamp.Seconds, Nanos: s.TxTimestamp.Nanos},
	})
}

// PutState writes a value (normal mock behaviour) and records it in the history.
func (s *Stub) PutState(key string, value []byte) error {
	if err := s.MockStub.PutState(key, value); err != nil {
		return err
	}
	s.record(key, value, false)
	return nil
}

// DelState deletes a key and records the delete in the history.
// (Used when a device moves to a new IP and the old address key is removed.)
func (s *Stub) DelState(key string) error {
	if err := s.MockStub.DelState(key); err != nil {
		return err
	}
	s.record(key, nil, true)
	return nil
}

// GetHistoryForKey returns modifications newest first, like a peer.
// The list is reversed here; GetDeviceHistory in device.go then sorts it
// oldest first, so it works the same on the mock and on a real peer.
func (s *Stub) GetHistoryForKey(key string) (shim.HistoryQueryIteratorInterface, error) {
	mods := s.history[key]
	rev := make([]*queryresult.KeyModification, len(mods))
	for i, m := range mods {
		rev[len(mods)-1-i] = m // first becomes last
	}
	return &histIter{items: rev}, nil
}

// histIter walks through a list of history entries one by one.
// It has the same three functions as a peer's history iterator.
type histIter struct {
	items []*queryresult.KeyModification
	i     int // position of the next item
}

func (h *histIter) HasNext() bool { return h.i < len(h.items) }
func (h *histIter) Close() error  { return nil } // nothing to free in memory
func (h *histIter) Next() (*queryresult.KeyModification, error) {
	if !h.HasNext() {
		return nil, fmt.Errorf("no more items")
	}
	h.i++
	return h.items[h.i-1], nil
}

// a small subset of CouchDB selectors
// Supports {"selector": {"field": value, "field": {"$gte": v, "$lte": v,
// "$gt": v, "$lt": v, "$eq": v}}}. Enough to test the phase 3 query.

// GetQueryResult returns every stored JSON document that matches the selector.
func (s *Stub) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	var q struct {
		Selector map[string]interface{} `json:"selector"`
	}
	if err := json.Unmarshal([]byte(query), &q); err != nil {
		return nil, fmt.Errorf("bad query: %w", err)
	}
	// sort the keys so the results always come back in the same order
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

// matches reports whether one document meets every condition in the selector.
// All conditions must be true (AND).
func matches(doc, sel map[string]interface{}) bool {
	for field, cond := range sel {
		val, ok := doc[field]
		if !ok {
			return false // field missing -> no match
		}
		if ops, isOps := cond.(map[string]interface{}); isOps {
			// condition with operators
			for op, want := range ops {
				c, comparable := compare(val, want) // c: -1 smaller, 0 equal, 1 bigger
				if !comparable {
					return false // different types
				}
				switch op {
				case "$eq": // equal
					if c != 0 {
						return false
					}
				case "$gt": // greater than
					if c <= 0 {
						return false
					}
				case "$gte": // greater than or equal
					if c < 0 {
						return false
					}
				case "$lt": // less than
					if c >= 0 {
						return false
					}
				case "$lte": // less than or equal
					if c > 0 {
						return false
					}
				default:
					return false // unsupported operator -> no match (safe default)
				}
			}
		} else if c, ok := compare(val, cond); !ok || c != 0 {
			// plain value
			return false
		}
	}
	return true
}

// compare returns -1, 0 or 1 (a smaller, equal, bigger than b) and whether
// the two values can be compared. Numbers, text and booleans are supported.
func compare(a, b interface{}) (int, bool) {
	switch av := a.(type) {
	case float64: // JSON numbers decode as float64
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
	case string: // text compares in alphabetical order (this is why timestamps are fixed width)
		bv, ok := b.(string)
		if !ok {
			return 0, false
		}
		return strings.Compare(av, bv), true
	case bool: // booleans can only be equal or not
		bv, ok := b.(bool)
		return 0, ok && av == bv
	}
	return 0, false
}

// kvIter walks through query results one by one (same idea as histIter).
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

// caller identities

// attrOID is the certificate extension Fabric CA uses for attributes.
var attrOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}

// Identity builds a serialized Fabric identity: an X.509 certificate with
// the given OU and, optionally, a "role" attribute, exactly as Fabric CA
// would issue them.
func Identity(mspID, commonName, ou, role string) []byte {
	// new P-256 key pair (errors are ignored: this is test code only)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),                                   // unique number
		Subject:      pkix.Name{CommonName: commonName, OrganizationalUnit: []string{ou}}, // name and OU
		NotBefore:    time.Now().Add(-time.Hour),                                          // valid from 1 hour ago
		NotAfter:     time.Now().Add(24 * time.Hour),                                      // valid for 24 hours
	}
	if role != "" {
		// Fabric CA stores attributes as JSON: {"attrs":{"role":"trustengine"}}
		val, _ := json.Marshal(map[string]map[string]string{"attrs": {"role": role}})
		tmpl.ExtraExtensions = []pkix.Extension{{Id: attrOID, Value: val}}
	}
	// self-signed certificate (template is both the subject and the issuer)
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Fabric sends the caller as MSP ID + certificate, encoded with protobuf
	sid := &msp.SerializedIdentity{Mspid: mspID, IdBytes: certPEM}
	b, _ := proto.Marshal(sid)
	return b
}
