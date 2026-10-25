// This file is the TrustContract: it records trust values sent by Member 1's
// trust engine. It is the core of Gap 1 (static trust).
//
// Each call does two things in one transaction:
//  1. updates the device's current record (trust value, status, counters)
//  2. adds a new TrustEvent record that is never changed afterwards
//
// Like all chaincode, it runs on every endorsing peer and every peer must get
// exactly the same result, so it uses the transaction time and rounds numbers.
package contracts

import (
	"encoding/json" // events are stored as JSON
	"fmt"           // error messages
	"math"          // math.Round for rounding to 2 decimals

	"github.com/hyperledger/fabric-contract-api-go/contractapi" // Fabric contract library

	"github.com/ztiot/ztiot-cc/models" // DeviceAsset and TrustEvent record types
)

// TrustContract records trust values continuously. This is contribution 1
// (Gap 1): trust is re-decided on every evaluation cycle from observed
// behaviour, instead of being assigned once at registration.
// Clients call it as "TrustContract:RecordTrustValue".
type TrustContract struct {
	contractapi.Contract
}

// RecordTrustValue writes one behaviour-derived trust value for a device.
// Allowed callers: the trust engine identity (role=trustengine) or an admin.
//
// It updates the current device record AND appends an immutable TrustEvent
// carrying the cause and a SHA-256 fingerprint of the evidence.
//
// Arguments, in order:
//
//	deviceID         e.g. "dev-004"
//	newValueText     new trust score, "0" to "100"
//	thresholdText    below this score the device becomes SUSPECT, "0" to "100"
//	attackClass      optional label from Member 2's AI, e.g. "ddos"
//	reasonCode       AI_ANOMALY, POLICY_VIOLATION, RECOVERY or MANUAL
//	evidencePayload  optional evidence text (only its hash is stored)
//	confidenceText   optional AI confidence, "0" to "1"
func (c *TrustContract) RecordTrustValue(
	ctx contractapi.TransactionContextInterface,
	deviceID string, newValueText string, thresholdText string,
	attackClass string, reasonCode string, evidencePayload string, confidenceText string,
) error {

	// 1. validate. Numbers arrive as text and are parsed here: the contract
	// API library crashes the chaincode process when a float parameter
	// receives "NaN" or "Inf" (found by negative testing), so float64
	// parameters are never used directly.
	// Every check happens before any ledger read or write (fail early).
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	// parseNumber (util.go) refuses empty text, text longer than 32
	// characters, NaN, infinity, hex such as "0x10" and values out of range.
	newValue, err := parseNumber("trust value", newValueText, 0, 100)
	if err != nil {
		return err
	}
	threshold, err := parseNumber("threshold", thresholdText, 0, 100)
	if err != nil {
		return err
	}
	confidence, err := parseNumber("confidence", confidenceText, 0, 1)
	if err != nil {
		return err
	}
	// allow-list: only the four known reason codes
	if !allowedReasonCodes[reasonCode] {
		return fmt.Errorf("unknown reason code: %s", reasonCode)
	}
	// label: up to 64 letters, digits or _.:- (blocks "<script>" and similar)
	if !labelPattern.MatchString(attackClass) {
		return fmt.Errorf("attackClass must be at most 64 letters, digits or _.:-")
	}
	// evidence limit (8192 bytes) so nobody can send huge transactions
	if len(evidencePayload) > maxEvidenceLen {
		return fmt.Errorf("evidence is longer than %d bytes", maxEvidenceLen)
	}

	// 2. authorise
	// Only the trust engine (role attribute set by the CA) or an admin may
	// change trust. A normal client gets "access denied".
	if err := requireRole(ctx, roleTrustEngine, roleAdmin); err != nil {
		return err
	}

	// 3. load
	// The device must already be registered.
	dev, err := readDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	// Transaction time: the same on every peer (time.Now() would differ).
	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}

	// round to 2 decimals so every peer stores exactly the same text
	// e.g. 71.239 -> 71.24. math.Round(x*100)/100 keeps 2 decimals.
	newValue = math.Round(newValue*100) / 100
	threshold = math.Round(threshold*100) / 100
	old := dev.TrustValue                         // value before this update
	delta := math.Round((newValue-old)*100) / 100 // change: negative = trust dropped

	// 4. update current state
	dev.TrustValue = newValue
	dev.Threshold = threshold
	dev.LastUpdated = ts
	dev.UpdateCount++ // total number of trust updates
	if delta < 0 {
		dev.DropCount++ // number of updates where trust went down
	}
	// keep only the latest 20 values (maxRecentValues) so the record cannot
	// grow for ever; the full list is still in the trust events
	dev.RecentValues = append(dev.RecentValues, newValue)
	if len(dev.RecentValues) > maxRecentValues {
		dev.RecentValues = dev.RecentValues[len(dev.RecentValues)-maxRecentValues:]
	}
	// The policy decision: below the threshold the device is SUSPECT,
	// otherwise ACTIVE. This is how a device recovers after good behaviour.
	if newValue < threshold {
		dev.Status = "SUSPECT"
	} else {
		dev.Status = "ACTIVE"
	}
	if _, err := writeDevice(ctx, dev); err != nil { // save under "DEVICE_<id>"
		return err
	}

	// 5. append the immutable trust event
	// A separate record for this one change. The contract has no function
	// to edit or delete events, so they form a permanent audit trail.
	ev := models.TrustEvent{
		DocType:      "trustEvent",
		EventID:      ctx.GetStub().GetTxID(), // transaction ID: unique and links to the block
		DeviceID:     deviceID,
		OldValue:     old,
		NewValue:     newValue,
		Delta:        delta,
		AttackClass:  attackClass,
		Confidence:   confidence,
		ReasonCode:   reasonCode,
		EvidenceHash: hashEvidence(evidencePayload), // SHA-256 only: raw evidence never goes on the ledger
		Timestamp:    ts,
		SubmitterMSP: submitterMSP(ctx), // which organisation sent the update
	}
	evBlob, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	// Key = (trustEvent, device ID, time). Keys sort by device then time,
	// so GetTrustEvents can read all events of one device in time order.
	ek, err := eventKey(ctx, deviceID, ts)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(ek, evBlob); err != nil {
		return fmt.Errorf("event write failed: %w", err)
	}
	// Tell listening applications that a trust value was recorded.
	return ctx.GetStub().SetEvent("TrustRecorded", evBlob)
}
