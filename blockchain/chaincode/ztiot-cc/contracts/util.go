package contracts

import (
	"crypto/sha256" // SHA-256 hash for evidence
	"encoding/hex"  // turn the hash bytes into 64 hex characters
	"encoding/json" // device records are stored as JSON
	"fmt"           // error messages
	"math"          // NaN and infinity checks
	"net"           // IP address parsing
	"regexp"        // patterns for IDs, hashes and labels
	"strconv"       // text -> number
	"strings"       // text helpers
	"time"          // format the transaction time

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/models"
)

const (
	maxRecentValues = 20   // trust values kept inside the device record
	maxEvidenceLen  = 8192 // largest evidence text accepted, in bytes

	// Fixed-width UTC timestamp. RFC3339Nano drops trailing zeros, which
	// makes text comparison of timestamps wrong ("05Z" sorts after "05.5Z").
	// A fixed width keeps string order equal to time order, which the
	// fleet-wide correlation query in phase 3 depends on.
	tsLayout = "2006-01-02T15:04:05.000000000Z"

	// composite key object types
	// The first part of a composite key, like a table name.
	eventKeyType = "trustEvent" // trust events: (trustEvent, device ID, time)
	addrKeyType  = "addr"       // address index: (addr, IP) -> device ID

	// roles
	roleAdmin       = "admin"       // may register and move devices, and write trust
	roleTrustEngine = "trustengine" // Member 1: may write trust values only
)

var (
	// ^ and $ = the whole text must match, not just part of it
	deviceIDPattern  = regexp.MustCompile(`^[A-Za-z0-9-]{3,64}$`)    // letters, digits, "-", 3 to 64 long
	hexSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)          // a SHA-256 value in lowercase hex
	labelPattern     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{0,64}$`) // attack class label, may be empty

	// Allow-lists: anything not listed is refused.
	// A map[string]bool returns false for a missing key, so
	// allowedDeviceTypes["toaster"] is false.
	allowedDeviceTypes = map[string]bool{
		"camera": true, "sensor": true, "actuator": true,
		"gateway": true, "meter": true, "lock": true,
	}

	allowedReasonCodes = map[string]bool{
		"AI_ANOMALY": true, "POLICY_VIOLATION": true,
		"RECOVERY": true, "MANUAL": true,
	}
)

// txTimestamp returns the deterministic transaction time.
// NEVER use time.Now() in chaincode: every endorsing peer would get a
// different value and endorsement would fail.
func txTimestamp(ctx contractapi.TransactionContextInterface) (string, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", fmt.Errorf("failed to read transaction timestamp: %w", err)
	}
	// seconds + nanoseconds -> fixed-width UTC text
	return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(tsLayout), nil
}

// callerRole returns the role of the identity that submitted the transaction.
// A "role" attribute in the certificate wins (set by the CA registrar, the
// caller cannot forge it). Otherwise an "admin" OU means administrator.
func callerRole(ctx contractapi.TransactionContextInterface) string {
	ci := ctx.GetClientIdentity() // the certificate that signed this transaction

	// 1. role attribute
	if v, found, err := ci.GetAttributeValue("role"); err == nil && found && v != "" {
		return v
	}
	// 2. otherwise check the Organizational Unit (OU) in the certificate
	cert, err := ci.GetX509Certificate()
	if err != nil || cert == nil {
		return "" // no certificate -> no role
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, roleAdmin) { // "admin", "Admin" or "ADMIN"
			return roleAdmin
		}
	}
	return "" // a normal client has no role
}

// requireRole denies by default: the caller must hold one of the listed roles.
func requireRole(ctx contractapi.TransactionContextInterface, allowed ...string) error {
	role := callerRole(ctx)
	for _, a := range allowed {
		if role == a {
			return nil // allowed: no error
		}
	}
	// no match (including an empty role) -> refused
	return fmt.Errorf("access denied: this operation requires role %s", strings.Join(allowed, " or "))
}

// Stored as the device owner and on every trust event.
func submitterMSP(ctx contractapi.TransactionContextInterface) string {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return ""
	}
	return msp
}

// hashEvidence produces the on-chain fingerprint. Raw evidence never goes on-chain.
// The same text always gives the same 64-character hash, so the original
// evidence (kept off-chain) can be checked later, but the hash alone does not
// reveal the evidence.
func hashEvidence(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:]) // 32 bytes -> 64 hex characters
}

// validateDeviceID checks a device ID against deviceIDPattern.
// Used by every contract function that takes a device ID.
func validateDeviceID(id string) error {
	if !deviceIDPattern.MatchString(id) {
		return fmt.Errorf("invalid device id: 3 to 64 characters, letters, digits or hyphen only")
	}
	return nil
}

// validateAddress accepts only a canonical dotted-quad IPv4 address.
// Leading zeros and IPv6 are rejected so the same device can never be
// stored under two spellings of one address.
func validateAddress(addr string) error {
	ip := net.ParseIP(addr)
	// ip == nil          -> not an IP at all ("abc", "999.1.1.1")
	// ip.To4() == nil    -> an IPv6 address ("::1")
	// String() != addr   -> not written in the standard way
	if ip == nil || ip.To4() == nil || ip.To4().String() != addr {
		return fmt.Errorf("network address must be a valid IPv4 address such as 192.168.10.44")
	}
	return nil
}

// keys

// deviceKey: key of a device record
func deviceKey(id string) string { return "DEVICE_" + id }

// eventKey: composite key (trustEvent, device ID, time) for one trust event.
// Fabric joins the parts with a special separator character, so a search on
// (trustEvent, device ID) finds all events of that device in time order.
func eventKey(ctx contractapi.TransactionContextInterface, id, ts string) (string, error) {
	return ctx.GetStub().CreateCompositeKey(eventKeyType, []string{id, ts})
}

// addrKey: composite key (addr, IP) for the address index. Its value is the
// device ID, so finding a device by IP is one key read.
func addrKey(ctx contractapi.TransactionContextInterface, ip string) (string, error) {
	return ctx.GetStub().CreateCompositeKey(addrKeyType, []string{ip})
}

// defaultThreshold sets the starting trust threshold from the criticality.
func defaultThreshold(criticality int) float64 {
	switch criticality {
	case 5:
		return 80.0
	case 4:
		return 70.0
	case 3:
		return 60.0
	case 2:
		return 50.0
	default: // criticality 1
		return 40.0
	}
}

// shared state access

// readDevice loads one device record from the ledger and decodes the JSON.
func readDevice(ctx contractapi.TransactionContextInterface, id string) (*models.DeviceAsset, error) {
	blob, err := ctx.GetStub().GetState(deviceKey(id))
	if err != nil {
		return nil, fmt.Errorf("state read failed: %w", err)
	}
	if blob == nil { // the key does not exist
		return nil, fmt.Errorf("device %s is not registered", id)
	}
	var dev models.DeviceAsset
	if err := json.Unmarshal(blob, &dev); err != nil {
		return nil, fmt.Errorf("stored record for %s is malformed", id)
	}
	// an empty list must be [] in the answer, not null
	if dev.RecentValues == nil {
		dev.RecentValues = []float64{}
	}
	return &dev, nil
}

// writeDevice encodes a device record as JSON and saves it. It returns the
// JSON so the caller can also use it as the event payload.
// PutState only takes effect if the whole transaction is valid when the block
// is committed.
func writeDevice(ctx contractapi.TransactionContextInterface, dev *models.DeviceAsset) ([]byte, error) {
	blob, err := json.Marshal(dev)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %w", err)
	}
	if err := ctx.GetStub().PutState(deviceKey(dev.DeviceID), blob); err != nil {
		return nil, fmt.Errorf("state write failed: %w", err)
	}
	return blob, nil
}

// parseNumber turns text into a finite number inside [min, max].
// NaN, infinity, hex and over-long input are refused.
// This is the NaN fix: trust.go takes numbers as text and calls this,
// because the contract library crashes on "NaN" for float64 parameters.
func parseNumber(name, text string, min, max float64) (float64, error) {
	// empty text, or longer than 32 characters (no real number needs more)
	if len(text) == 0 || len(text) > 32 {
		return 0, fmt.Errorf("%s must be between %g and %g", name, min, max)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	// refused when: not a number, NaN, infinity (also "1e309", which is too
	// big), outside min..max, or written with x/p/_ (hex forms like "0x10")
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < min || v > max ||
		strings.ContainsAny(text, "xXpP_") {
		return 0, fmt.Errorf("%s must be between %g and %g", name, min, max)
	}
	return v, nil
}
