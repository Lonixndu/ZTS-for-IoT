package contracts_test

import (
	"encoding/json" // decode the JSON the contract returns
	"fmt"           // build values such as "90", "89", ... in loops
	"strings"       // check error messages and output text
	"testing"       // Go's built-in test framework

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/contracts" // the code being tested
	"github.com/ztiot/ztiot-cc/fakestub"  // in-memory ledger and test certificates
	"github.com/ztiot/ztiot-cc/models"    // DeviceAsset, TrustEvent and other record types
)

// test identities, built the way Fabric CA issues them
// Identity(MSP, name, OU, role attribute). The contract decides permissions
// from these certificates, so the tests check the real access control.
var (
	admin       = fakestub.Identity("Org1MSP", "org1admin", "admin", "")                // administrator (OU = admin)
	trustEngine = fakestub.Identity("Org1MSP", "trustengine1", "client", "trustengine") // Member 1's identity (role = trustengine)
	plainClient = fakestub.Identity("Org1MSP", "user1", "client", "")                   // normal user: may read, may not write
)

// A valid identity hash for tests: 64 hex characters, the length of a SHA-256 value.
const camHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Helper functions
// t.Helper() makes a failure report the line in the test that called the
// helper, not a line inside the helper, so failures are easier to find.

// newLedger builds the chaincode and a new empty ledger for one test.
func newLedger(t *testing.T) (*contractapi.ContractChaincode, *fakestub.Stub) {
	t.Helper()
	cc, err := contractapi.NewChaincode(&contracts.DeviceContract{}, &contracts.TrustContract{})
	if err != nil {
		t.Fatalf("NewChaincode: %v", err) // Fatalf = report the error and stop this test
	}
	return cc, fakestub.New("ztiot", cc)
}

// ok runs a contract function that MUST succeed and returns its output.
// "who" is the identity that sends the transaction.
func ok(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, who []byte, fn string, args ...string) []byte {
	t.Helper()
	r := s.Invoke(cc, who, fn, args...)
	if r.Status != 200 { // 200 = success
		t.Fatalf("%s(%v) failed: %s", fn, args, r.Message)
	}
	return r.Payload
}

// fails runs a contract function that MUST be rejected, and checks that the
// error message contains wantMsg. Checking the message proves it failed for
// the right reason, not because of some other bug.
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

// register adds a device as the admin. Arguments: id, type, criticality, IP.
func register(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, id, typ, crit, ip string) {
	t.Helper()
	ok(t, cc, s, admin, "DeviceContract:RegisterDevice", id, typ, crit, camHash, ip)
}

// getDevice reads a device record (as a plain client) and decodes the JSON.
func getDevice(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, id string) models.DeviceAsset {
	t.Helper()
	var d models.DeviceAsset
	if err := json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDevice", id), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// trust records a trust value as the trust engine, with fixed test values:
// threshold 70, no attack class, reason AI_ANOMALY, evidence "evidence", confidence 0.9.
func trust(t *testing.T, cc *contractapi.ContractChaincode, s *fakestub.Stub, id, value string) {
	t.Helper()
	ok(t, cc, s, trustEngine, "TrustContract:RecordTrustValue", id, value, "70", "", "AI_ANOMALY", "evidence", "0.9")
}

// Tests. Go runs every function whose name starts with "Test".

// TC-01: an administrator registers a device
func TestRegisterDevice(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")

	// A new device starts fully trusted (100) and ACTIVE.
	// Criticality 4 gives the default threshold 70.
	d := getDevice(t, cc, s, "dev-004")
	if d.TrustValue != 100 || d.Threshold != 70 || d.Status != "ACTIVE" {
		t.Fatalf("unexpected initial state: %+v", d) // %+v prints the struct with field names
	}
	// The given values are stored, and the owner is taken from the caller's MSP.
	if d.NetworkAddress != "192.168.10.44" || d.DeviceType != "camera" || d.Owner != "Org1MSP" {
		t.Fatalf("fields not stored: %+v", d)
	}
}

// TC-02: only an administrator may register
// Least privilege: a normal user and even the trust engine are refused.
func TestRegisterDeniedForNonAdmin(t *testing.T) {
	cc, s := newLedger(t)
	fails(t, cc, s, plainClient, "access denied", "DeviceContract:RegisterDevice", "dev-004", "camera", "4", camHash, "192.168.10.44")
	fails(t, cc, s, trustEngine, "access denied", "DeviceContract:RegisterDevice", "dev-004", "camera", "4", camHash, "192.168.10.44")
}

// TC-03 and TC-13: duplicates are refused, not overwritten
func TestRegisterDuplicates(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	// same device ID again -> refused (an attacker cannot replace a device record)
	fails(t, cc, s, admin, "already registered", "DeviceContract:RegisterDevice", "dev-004", "sensor", "2", camHash, "192.168.10.99")
	// a new device on an IP that is already used -> refused (one IP = one device)
	fails(t, cc, s, admin, "already assigned", "DeviceContract:RegisterDevice", "dev-005", "sensor", "2", camHash, "192.168.10.44")
}

// TC-14 and input validation for registration
// Table-driven test: each row is one bad input and the error it must cause.
func TestRegisterValidation(t *testing.T) {
	cc, s := newLedger(t)
	cases := []struct{ msg, id, typ, crit, hash, ip string }{
		{"invalid device id", "d", "camera", "4", camHash, "10.0.0.1"},              // ID too short
		{"invalid device id", "dev 004; DROP", "camera", "4", camHash, "10.0.0.1"},  // space and ";" (injection attempt)
		{"unsupported device type", "dev-001", "toaster", "4", camHash, "10.0.0.1"}, // type not in the allowed list
		{"criticality", "dev-001", "camera", "9", camHash, "10.0.0.1"},              // criticality must be 1 to 5
		{"identityHash", "dev-001", "camera", "4", "notahash", "10.0.0.1"},          // not 64 hex characters
		{"IPv4", "dev-001", "camera", "4", camHash, "999.1.1.1"},                    // number above 255
		{"IPv4", "dev-001", "camera", "4", camHash, "192.168.010.044"},              // leading zeros (not canonical)
		{"IPv4", "dev-001", "camera", "4", camHash, "::1"},                          // IPv6 is not accepted
		{"IPv4", "dev-001", "camera", "4", camHash, `"}],"$or":[{"a":"`},            // CouchDB query injection attempt
	}
	for _, c := range cases {
		fails(t, cc, s, admin, c.msg, "DeviceContract:RegisterDevice", c.id, c.typ, c.crit, c.hash, c.ip)
	}
}

// TC-04: a trust drop below the limit marks the device SUSPECT and writes an event
func TestRecordTrustValue(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	trust(t, cc, s, "dev-004", "85") // 100 -> 85: a drop, still above 70
	trust(t, cc, s, "dev-004", "60") // 85 -> 60: a drop, now below 70

	// Two updates, both were drops, and 60 < 70 so the device is SUSPECT.
	d := getDevice(t, cc, s, "dev-004")
	if d.TrustValue != 60 || d.Status != "SUSPECT" || d.UpdateCount != 2 || d.DropCount != 2 {
		t.Fatalf("unexpected state after drops: %+v", d)
	}

	// Every trust change is also stored as a separate event record (audit trail).
	var evs []models.TrustEvent
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetTrustEvents", "dev-004"), &evs)
	if len(evs) != 2 {
		t.Fatalf("want 2 trust events, got %d", len(evs))
	}
	// The second event records the old value, the new value and the change.
	if evs[1].OldValue != 85 || evs[1].NewValue != 60 || evs[1].Delta != -25 {
		t.Fatalf("second event wrong: %+v", evs[1])
	}
	// Evidence text is not stored on the ledger. Only its SHA-256 hash
	// (64 hex characters) is stored, so the record stays small and private
	// but the original evidence can still be proved later.
	if len(evs[0].EvidenceHash) != 64 || evs[0].EvidenceHash == "evidence" {
		t.Fatalf("evidence must be stored as a SHA-256 fingerprint, got %q", evs[0].EvidenceHash)
	}
	// Events are in time order (timestamps are text in ISO format, so >= compares them correctly).
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
	// a normal user cannot lower a device's trust
	fails(t, cc, s, plainClient, "access denied", "TrustContract:RecordTrustValue", "dev-004", "10", "70", "", "AI_ANOMALY", "", "0.5")
	// an admin can (manual correction)
	ok(t, cc, s, admin, "TrustContract:RecordTrustValue", "dev-004", "95", "70", "", "MANUAL", "", "0")
}

// TC-05 and TC-06: out-of-range values and unknown reason codes are rejected
// Argument order: device, trust value, threshold, attack class, reason, evidence, confidence.
func TestRecordTrustValidation(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	fails(t, cc, s, trustEngine, "between 0 and 100", "TrustContract:RecordTrustValue", "dev-004", "150", "70", "", "AI_ANOMALY", "", "0.5")  // trust above 100
	fails(t, cc, s, trustEngine, "between 0 and 100", "TrustContract:RecordTrustValue", "dev-004", "-1", "70", "", "AI_ANOMALY", "", "0.5")   // trust below 0
	fails(t, cc, s, trustEngine, "confidence", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "", "AI_ANOMALY", "", "2")            // confidence above 1
	fails(t, cc, s, trustEngine, "unknown reason code", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "", "HACKED", "", "0.5")     // reason not in the list
	fails(t, cc, s, trustEngine, "attackClass", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "<script>", "AI_ANOMALY", "", "0.5") // script injection in the label
	fails(t, cc, s, trustEngine, "not registered", "TrustContract:RecordTrustValue", "dev-999", "50", "70", "", "AI_ANOMALY", "", "0.5")      // unknown device
}

// TC-07: the recent-values buffer is capped at 20 so the record cannot grow for ever
func TestRecentValuesBounded(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	// send 30 values: 90, 89, 88, ..., 61
	for i := 0; i < 30; i++ {
		trust(t, cc, s, "dev-004", fmt.Sprintf("%d", 90-i))
	}
	// only the latest 20 are kept, and the newest (61) is at the end
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

	// IP -> the right device, its type and its latest trust value
	var r models.AddressLookupResult
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceByAddress", "192.168.10.44"), &r)
	if r.DeviceID != "dev-004" || r.DeviceType != "camera" || r.TrustValue != 76.4 {
		t.Fatalf("lookup returned wrong device: %+v", r)
	}
	// The lookup result must not leak the identity hash (data minimisation).
	raw := string(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceByAddress", "192.168.10.45"))
	if strings.Contains(raw, "identityHash") || strings.Contains(raw, camHash) {
		t.Fatalf("lookup must not reveal the identity hash: %s", raw)
	}
	// unknown IP -> clear error; text that is not an IP -> validation error
	fails(t, cc, s, plainClient, "no device is registered at that address", "DeviceContract:GetDeviceByAddress", "10.0.0.99")
	fails(t, cc, s, plainClient, "IPv4", "DeviceContract:GetDeviceByAddress", "not-an-ip")
}

// TC-15 and TC-16: changing an address releases the old one and keeps history
func TestUpdateDeviceAddressAndHistory(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	register(t, cc, s, "dev-005", "lock", "5", "192.168.10.45")

	fails(t, cc, s, plainClient, "access denied", "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.50") // only admin may move a device
	fails(t, cc, s, admin, "already assigned", "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.45")    // cannot take dev-005's IP
	ok(t, cc, s, admin, "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.50")                           // valid move

	// the old IP no longer points to any device; the new IP points to dev-004
	fails(t, cc, s, plainClient, "no device", "DeviceContract:GetDeviceByAddress", "192.168.10.44")
	var r models.AddressLookupResult
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceByAddress", "192.168.10.50"), &r)
	if r.DeviceID != "dev-004" {
		t.Fatalf("new address should resolve to dev-004, got %+v", r)
	}
	// the released address can be reused by a new device
	register(t, cc, s, "dev-006", "sensor", "2", "192.168.10.44")

	// The ledger history keeps every version of the record:
	// 1 = registered, 2 = address changed, 3 = trust updated.
	trust(t, cc, s, "dev-004", "80")
	var h []models.HistoryEntry
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetDeviceHistory", "dev-004"), &h)
	if len(h) != 3 {
		t.Fatalf("want 3 history versions (register, move, trust), got %d", len(h))
	}
	if h[0].Record.NetworkAddress != "192.168.10.44" || h[1].Record.NetworkAddress != "192.168.10.50" {
		t.Fatalf("history should show the old then the new address: %+v", h)
	}
	// each version has a transaction ID and the versions are in time order
	if h[2].Record.TrustValue != 80 || h[0].TxID == "" || h[0].Timestamp >= h[2].Timestamp {
		t.Fatalf("history entries out of order or incomplete: %+v", h)
	}
}

// responses must pass contractapi schema validation even when empty
// An empty list must be returned as [] and not null, otherwise the contract
// library rejects the response.
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
// These cover the remaining error branches, which raises the code coverage.
func TestEdgeCases(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")

	if got := string(ok(t, cc, s, plainClient, "DeviceContract:DeviceExists", "dev-004")); got != "true" {
		t.Fatalf("DeviceExists should be true, got %s", got)
	}
	// every read function checks the device ID ("x" is too short)
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:GetDevice", "x")
	fails(t, cc, s, plainClient, "not registered", "DeviceContract:GetDevice", "dev-404")
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:DeviceExists", "x")
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:GetTrustEvents", "x")
	fails(t, cc, s, plainClient, "invalid device id", "DeviceContract:GetDeviceHistory", "x")
	// address update errors: same address, unknown device, bad IP, bad ID
	fails(t, cc, s, admin, "already has address", "DeviceContract:UpdateDeviceAddress", "dev-004", "192.168.10.44")
	fails(t, cc, s, admin, "not registered", "DeviceContract:UpdateDeviceAddress", "dev-404", "192.168.10.60")
	fails(t, cc, s, admin, "IPv4", "DeviceContract:UpdateDeviceAddress", "dev-004", "300.0.0.1")
	fails(t, cc, s, admin, "invalid device id", "DeviceContract:UpdateDeviceAddress", "x", "192.168.10.60")
	// trust errors: threshold above 100, bad ID, evidence longer than the limit (9,000 characters)
	fails(t, cc, s, trustEngine, "threshold", "TrustContract:RecordTrustValue", "dev-004", "50", "101", "", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "invalid device id", "TrustContract:RecordTrustValue", "x", "50", "70", "", "AI_ANOMALY", "", "0.5")
	fails(t, cc, s, trustEngine, "longer than", "TrustContract:RecordTrustValue", "dev-004", "50", "70", "", "AI_ANOMALY", strings.Repeat("x", 9000), "0.5")
	// threshold values are rounded to 2 decimals so every peer stores identical text
	// 71.239 -> 71.24 and 70.004 -> 70. If peers stored different text, their
	// results would not match and Fabric would reject the transaction.
	ok(t, cc, s, trustEngine, "TrustContract:RecordTrustValue", "dev-004", "71.239", "70.004", "", "AI_ANOMALY", "", "0.5")
	if d := getDevice(t, cc, s, "dev-004"); d.TrustValue != 71.24 || d.Threshold != 70 {
		t.Fatalf("values should be rounded to 2 decimals: %+v", d)
	}
}

// the ledger must keep working past 100 transactions (regression test for a
// mock-stub event channel that blocked after 100 events)
// A regression test makes sure a bug that was fixed does not come back.
func TestManyTransactions(t *testing.T) {
	cc, s := newLedger(t)
	register(t, cc, s, "dev-004", "camera", "4", "192.168.10.44")
	// 250 trust updates with values between 50 and 99
	for i := 0; i < 250; i++ {
		trust(t, cc, s, "dev-004", fmt.Sprintf("%d", 50+i%50))
	}
	// all 250 events stored, and the last event name is "TrustRecorded"
	var evs []models.TrustEvent
	json.Unmarshal(ok(t, cc, s, plainClient, "DeviceContract:GetTrustEvents", "dev-004"), &evs)
	if len(evs) != 250 || s.LastEvent != "" && s.LastEvent != "TrustRecorded" {
		t.Fatalf("want 250 events, got %d (last event %q)", len(evs), s.LastEvent)
	}
}
