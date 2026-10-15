package contracts_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/contracts"
	"github.com/ztiot/ztiot-cc/fakestub"
	"github.com/ztiot/ztiot-cc/models"
)

// test identities, built the way Fabric CA issues them
var (
	admin       = fakestub.Identity("Org1MSP", "org1admin", "admin", "")
	trustEngine = fakestub.Identity("Org1MSP", "trustengine1", "client", "trustengine")
	plainClient = fakestub.Identity("Org1MSP", "user1", "client", "")
)

const camHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newLedger(t *testing.T) (*contractapi.ContractChaincode, *fakestub.Stub) {
	t.Helper()
	cc, err := contractapi.NewChaincode(&contracts.DeviceContract{}, &contracts.TrustContract{})
	if err != nil {
		t.Fatalf("NewChaincode: %v", err)
	}
	return cc, fakestub.New("ztiot", cc)
}

func ok(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, who []byte, fn string, args ...string) []byte {
	t.Helper()
	r := s.Invoke(cc, who, fn, args...)
	if r.Status != 200 {
		t.Fatalf("%s(%v) failed: %s", fn, args, r.Message)
	}
	return r.Payload
}

func fails(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, who []byte, wantMsg, fn string, args ...string) {
	t.Helper()
	r := s.Invoke(cc, who, fn, args...)
	if r.Status == 200 {
		t.Fatalf("%s(%v) should have failed but succeeded", fn, args)
	}
	if !strings.Contains(r.Message, wantMsg) {
		t.Fatalf("%s(%v): want error containing %q, got %q", fn, args, wantMsg, r.Message)
	}
}

func register(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, id, typ, crit, ip string) {
	t.Helper()
	ok(t, cc, s, admin, "DeviceContract:RegisterDevice", id, typ, crit, camHash, ip)
}

func getDevice(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, id string) models.DeviceAsset {
	t.Helper()
	var d models.DeviceAsset
	if err := json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDevice", id), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func trust(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, id, value string) {
	t.Helper()
	ok(t, cc, s, trustEngine, "TrustContract:RecordTrustValue", id, value, "70", "", "AI_ANOMALY", "evidence", "0.9")
}

// TC-01: an administrator registers a device
func TestRegisterDevice(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")

	d := getDevice(t, cc, s, "dev-004")
	if d.TrustValue != 100 || d.Threshold != 70 || d.Status != "ACTIVE" {
		t.Fatalf("unexpected initial state: %+v", d)
	}
	if d.NetworkAddress != "192.168.10.44" || d.DeviceType != "camera" || d.Owner != "Org1MSP" {
		t.Fatalf("fields not stored: %+v", d)
	}
}

// TC-02: only an administrator may register
func TestRegisterDeniedForNonAdmin(t *testing.T) {
	cc, s := newLedger(t)
	fails(t, cc, s, plainClient, "access denied", "DeviceContract:RegisterDevice", "dev-004", "camera", "4", camHash, "192.168.10.44")
	fails(t, cc, s, trustEngine, "access denied", "DeviceContract:RegisterDevice", "dev-004", "camera", "4", camHash, "192.168.10.44")
}

// TC-03 and TC-13: duplicates are refused, not overwritten
func TestRegisterDuplicates(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	fails(t, cc, s, admin, "already registered", "DeviceContract:RegisterDevice", "dev-004", "sensor", "2", camHash, "192.168.10.99")
	fails(t, cc, s, admin, "already assigned", "DeviceContract:RegisterDevice", "dev-005", "sensor", "2", camHash, "192.168.10.44")
}

// TC-14 and input validation for registration
func TestRegisterValidation(t *testing.T) {
	cc, s := newLedger(t)
	cases := []struct{ msg, id, typ, crit, hash, ip string }{
		{"invalid device id", "d", "camera", "4", camHash, "10.0.0.1"},
		{"invalid device id", "dev 004; DROP", "camera", "4", camHash, "10.0.0.1"},
		{"unsupported device type", "dev-001", "toaster", "4", camHash, "10.0.0.1"},
		{"criticality", "dev-001", "camera", "9", camHash, "10.0.0.1"},
		{"identityHash", "dev-001", "camera", "4", "notahash", "10.0.0.1"},
		{"IPv4", "dev-001", "camera", "4", camHash, "999.1.1.1"},
		{"IPv4", "dev-001", "camera", "4", camHash, "192.168.010.044"},
		{"IPv4", "dev-001", "camera", "4", camHash, "::1"},
		{"IPv4", "dev-001", "camera", "4", camHash, `"}],"$or":[{"a":"`},
	}
	for _, c := range cases {
		fails(t, cc, s, admin, c.msg, "DeviceContract:RegisterDevice", c.id, c.typ, c.crit, c.hash, c.ip)
	}
}

// TC-04: a trust drop below the limit marks the device SUSPECT and writes an event
func TestRecordTrustValue(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	trust(t, cc, s, "dev-004", "85")
	trust(t, cc, s, "dev-004", "60")

	d := getDevice(t, cc, s, "dev-004")
	if d.TrustValue != 60 || d.Status != "SUSPECT" || d.UpdateCount != 2 || d.DropCount != 2 {
		t.Fatalf("unexpected state after drops: %+v", d)
	}

	var evs []models.TrustEvent
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetTrustEvents", "dev-004"), &evs)
	if len(evs) != 2 {
		t.Fatalf("want 2 trust events, got %d", len(evs))
	}
	if evs[1].OldValue != 85 || evs[1].NewValue != 60 || evs[1].Delta != -25 {
		t.Fatalf("second event wrong: %+v", evs[1])
	}
	if len(evs[0].EvidenceHash) != 64 || evs[0].EvidenceHash == "evidence" {
		t.Fatalf("evidence must be stored as a SHA-256 fingerprint, got %q", evs[0].EvidenceHash)
	}
	if evs[0].Timestamp >= evs[1].Timestamp {
		t.Fatalf("events not in time order: %s then %s", evs[0].Timestamp, evs[1].Timestamp)
	}

	// recovery returns the device to ACTIVE
	ok(t, cc, s, trustEngine, "TrustContract:RecordTrustValue", "dev-004", "90", "70", "", "RECOVERY", "", "0")
	if d := getDevice(t, cc, s, "dev-004"); d.Status != "ACTIVE" {
		t.Fatalf("device should recover to ACTIVE, got %s", d.Status)
	}
}

// only the trust engine or an administrator may write trust values
func TestRecordTrustDeniedForPlainClient(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	fails(t, cc, s, plainClient, "access denied", "TrustContract:RecordTrustValue", "dev-004", "10", "70", "", "AI_ANOMALY", "", "0.5")
	ok(t, cc, s, admin, "TrustContract:RecordTrustValue", "dev-004", "95", "70", "", "MANUAL", "", "0")
}

// TC-05 and TC-06: out-of-range values and unknown reason codes are rejected
func TestRecordTrustValidation(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	fails(t, cc, s, trustEngine, "between 0 and 100", "TrustContract:RecordTrustValue", "dev-004", "150", "70", "", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "between 0 and 100", "TrustContract:RecordTrustValue", "dev-004", "-1", "70", "", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "confidence", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "", "AI_ANOMALY", "", "2")
	fails(t, cc, s, trustEngine, "unknown reason code", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "", "HACKED", "", "0.5")
	fails(t, cc, s, trustEngine, "attackClass", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "<script>", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "not registered", "TrustContract:RecordTrustValue", "dev-999", "50", "70", "", "AI_ANOMALY", "", "0.5")
}

// TC-07: the recent-values buffer is capped at 20 so the record cannot grow for ever
func TestRecentValuesBounded(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	for i := 0; i < 30; i++ {
		trust(t, cc, s, "dev-004", fmt.Sprintf("%d", 90-i))
	}
	d := getDevice(t, cc, s, "dev-004")
	if len(d.RecentValues) != 20 {
		t.Fatalf("recentValues should be capped at 20, got %d", len(d.RecentValues))
	}
	if d.RecentValues[19] != 61 {
		t.Fatalf("newest value should be last, got %v", d.RecentValues)
	}
}

// TC-11 and TC-12: Member 4 looks a device up by IP address
func TestGetDeviceByAddress(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	register(t, cc, s, "dev-005", "lock", "5", "192.168.10.45")
	trust(t, cc, s, "dev-004", "76.4")

	var r models.AddressLookupResult
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceByAddress", "192.168.10.44"), &r)
	if r.DeviceID != "dev-004" || r.DeviceType != "camera" || r.TrustValue != 76.4 {
		t.Fatalf("lookup returned wrong device: %+v", r)
	}
	raw := string(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceByAddress", "192.168.10.45"))
	if strings.Contains(raw, "identityHash") || strings.Contains(raw, camHash) {
		t.Fatalf("lookup must not reveal the identity hash: %s", raw)
	}
	fails(t, cc, s, plainClient, "no device is registered at that address", "DeviceContract:GetDeviceByAddress", "10.0.0.99")
	fails(t, cc, s, plainClient, "IPv4", "DeviceContract:GetDeviceByAddress", "not-an-ip")
}

// TC-15 and TC-16: changing an address releases the old one and keeps history
func TestUpdateDeviceAddressAndHistory(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	register(t, cc, s, "dev-005", "lock", "5", "192.168.10.45")

	fails(t, cc, s, plainClient, "access denied", "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.50")
	fails(t, cc, s, admin, "already assigned", "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.45")
	ok(t, cc, s, admin, "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.50")

	fails(t, cc, s, plainClient, "no device", "DeviceContract:GetDeviceByAddress", "192.168.10.44")
	var r models.AddressLookupResult
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceByAddress", "192.168.10.50"), &r)
	if r.DeviceID != "dev-004" {
		t.Fatalf("new address should resolve to dev-004, got %+v", r)
	}
	// the released address can be reused by a new device
	register(t, cc, s, "dev-006", "sensor", "2", "192.168.10.44")

	trust(t, cc, s, "dev-004", "80")
	var h []models.HistoryEntry
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceHistory", "dev-004"), &h)
	if len(h) != 3 {
		t.Fatalf("want 3 history versions (register, move, trust), got %d", len(h))
	}
	if h[0].Record.NetworkAddress != "192.168.10.44" || h[1].Record.NetworkAddress != "192.168.10.50" {
		t.Fatalf("history should show the old then the new address: %+v", h)
	}
	if h[2].Record.TrustValue != 80 || h[0].TxID == "" || h[0].Timestamp >= h[2].Timestamp {
		t.Fatalf("history entries out of order or incomplete: %+v", h)
	}
}

// responses must pass contractapi schema validation even when empty
func TestEmptyResultsAreArraysNotNull(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	if got := string(ok(t, cc, s, plainClient, "DeviceContract:GetTrustEvents", "dev-004")); got != "[]" {
		t.Fatalf("want [] for a device with no events, got %s", got)
	}
	if got := string(ok(t, cc, s, plainClient, "DeviceContract:DeviceExists", "dev-404")); got != "false" {
		t.Fatalf("DeviceExists should be false, got %s", got)
	}
}

// edge cases on reads and address updates
func TestEdgeCases(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")

	if got := string(ok(t, cc, s, plainClient, "DeviceContract:DeviceExists", "dev-004")); got != "true" {
		t.Fatalf("DeviceExists should be true, got %s", got)
	}
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:GetDevice", "x")
	fails(t, cc, s, plainClient, "not registered", "DeviceContract:GetDevice", "dev-404")
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:DeviceExists", "x")
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:GetTrustEvents", "x")
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:GetDeviceHistory", "x")
	fails(t, cc, s, admin, "already has address", "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.44")
	fails(t, cc, s, admin, "not registered", "DeviceContract:UpdateDeviceAddress", "dev-404", "192.168.10.60")
	fails(t, cc, s, admin, "IPv4", "DeviceContract:UpdateDeviceAddress", "dev-004", "300.0.0.1")
	fails(t, cc, s, admin, "invalid device id", "DeviceContract:UpdateDeviceAddress", "x", "192.168.10.60")
	fails(t, cc, s, trustEngine, "threshold", "TrustContract:RecordTrustValue", "dev-004", "50", "101", "", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "invalid device id", "TrustContract:RecordTrustValue", "x", "50", "70", "", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "longer than", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "", "AI_ANOMALY", strings.Repeat("x", 9000), "0.5")
	// threshold values are rounded to 2 decimals so every peer stores identical text
	ok(t, cc, s, trustEngine, "TrustContract:RecordTrustValue", "dev-004", "71.239", "70.004", "", "AI_ANOMALY", "", "0.5")
	if d := getDevice(t, cc, s, "dev-004"); d.TrustValue != 71.24 || d.Threshold != 70 {
		t.Fatalf("values should be rounded to 2 decimals: %+v", d)
	}
}

// the ledger must keep working past 100 transactions (regression test for a
// mock-stub event channel that blocked after 100 events)
func TestManyTransactions(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	for i := 0; i < 250; i++ {
		trust(t, cc, s, "dev-004", fmt.Sprintf("%d", 50+i%50))
	}
	var evs []models.TrustEvent
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetTrustEvents", "dev-004"), &evs)
	if len(evs) != 250 || s.LastEvent != "" && s.LastEvent != "TrustRecorded" {
		t.Fatalf("want 250 events, got %d (last event %q)", len(evs), s.LastEvent)
	}
}
