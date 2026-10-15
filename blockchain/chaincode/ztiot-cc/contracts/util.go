// Package contracts holds the smart contract transactions.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/models"
)

const (
	maxRecentValues = 20
	maxEvidenceLen  = 8192

	// Fixed-width UTC timestamp. RFC3339Nano drops trailing zeros, which
	// makes text comparison of timestamps wrong ("05Z" sorts after "05.5Z").
	// A fixed width keeps string order equal to time order, which the
	// fleet-wide correlation query in phase 3 depends on.
	tsLayout = "2006-01-02T15:04:05.000000000Z"

	// composite key object types
	eventKeyType = "trustEvent"
	addrKeyType  = "addr"

	// roles
	roleAdmin       = "admin"
	roleTrustEngine = "trustengine"
)

var (
	deviceIDPattern  = regexp.MustCompile(`^[A-Za-z0-9-]{3,64}$`)
	hexSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	labelPattern     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{0,64}$`)

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
	return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(tsLayout), nil
}

// callerRole returns the role of the identity that submitted the transaction.
// A "role" attribute in the certificate wins (set by the CA registrar, the
// caller cannot forge it). Otherwise an "admin" OU means administrator.
func callerRole(ctx contractapi.TransactionContextInterface) string {
	ci := ctx.GetClientIdentity()
	if v, found, err := ci.GetAttributeValue("role"); err == nil && found && v != "" {
		return v
	}
	cert, err := ci.GetX509Certificate()
	if err != nil || cert == nil {
		return ""
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, roleAdmin) {
			return roleAdmin
		}
	}
	return ""
}

// requireRole denies by default: the caller must hold one of the listed roles.
func requireRole(ctx contractapi.TransactionContextInterface, allowed ...string) error {
	role := callerRole(ctx)
	for _, a := range allowed {
		if role == a {
			return nil
		}
	}
	return fmt.Errorf("access denied: this operation requires role %s", strings.Join(allowed, " or "))
}

func submitterMSP(ctx contractapi.TransactionContextInterface) string {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return ""
	}
	return msp
}

// hashEvidence produces the on-chain fingerprint. Raw evidence never goes on-chain.
func hashEvidence(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

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
	if ip == nil || ip.To4() == nil || ip.To4().String() != addr {
		return fmt.Errorf("network address must be a valid IPv4 address such as 192.168.10.44")
	}
	return nil
}

// ---- keys -------------------------------------------------------------

func deviceKey(id string) string { return "DEVICE_" + id }

func eventKey(ctx contractapi.TransactionContextInterface, id, ts string) (string, error) {
	return ctx.GetStub().CreateCompositeKey(eventKeyType, []string{id, ts})
}

func addrKey(ctx contractapi.TransactionContextInterface, ip string) (string, error) {
	return ctx.GetStub().CreateCompositeKey(addrKeyType, []string{ip})
}

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
	default:
		return 40.0
	}
}

// ---- shared state access ---------------------------------------------

func readDevice(ctx contractapi.TransactionContextInterface, id string) (*models.DeviceAsset, error) {
	blob, err := ctx.GetStub().GetState(deviceKey(id))
	if err != nil {
		return nil, fmt.Errorf("state read failed: %w", err)
	}
	if blob == nil {
		return nil, fmt.Errorf("device %s is not registered", id)
	}
	var dev models.DeviceAsset
	if err := json.Unmarshal(blob, &dev); err != nil {
		return nil, fmt.Errorf("stored record for %s is malformed", id)
	}
	if dev.RecentValues == nil {
		dev.RecentValues = []float64{}
	}
	return &dev, nil
}

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
