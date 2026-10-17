package contracts

import (
	"encoding/json" // events are stored as JSON
	"fmt"           // error messages
	"math"          // math.Round for rounding to 2 decimals

	"github.com/hyperledger/fabric-contract-api-go/contractapi" // Fabric contract library

	"github.com/ztiot/ztiot-cc/models" // DeviceAsset and TrustEvent record types
)

// TrustContract records trust values continuously.
type TrustContract struct {
	contractapi.Contract
}

// RecordTrustValue writes one behaviour-derived trust value for a device.
func (c *TrustContract) RecordTrustValue(
	ctx contractapi.TransactionContextInterface,
	deviceID string, newValue float64, threshold float64,
	attackClass string, reasonCode string, evidencePayload string, confidence float64,
) error {

	// 1. validate
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	if math.IsNaN(newValue) || newValue < 0 || newValue > 100 {
		return fmt.Errorf("trust value must be between 0 and 100")
	}
	if math.IsNaN(threshold) || threshold < 0 || threshold > 100 {
		return fmt.Errorf("threshold must be between 0 and 100")
	}
	if math.IsNaN(confidence) || confidence < 0 || confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	if !allowedReasonCodes[reasonCode] {
		return fmt.Errorf("unknown reason code: %s", reasonCode)
	}
	if !labelPattern.MatchString(attackClass) {
		return fmt.Errorf("attackClass must be at most 64 letters, digits or _.:-")
	}
	if len(evidencePayload) > maxEvidenceLen {
		return fmt.Errorf("evidence is longer than %d bytes", maxEvidenceLen)
	}

	// 2. authorise
	if err := requireRole(ctx, roleTrustEngine, roleAdmin); err != nil {
		return err
	}

	// 3. load
	dev, err := readDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}

	// round to 2 decimals so every peer stores exactly the same text
	newValue = math.Round(newValue*100) / 100
	threshold = math.Round(threshold*100) / 100
	old := dev.TrustValue
	delta := math.Round((newValue-old)*100) / 100

	// 4. update current state
	dev.TrustValue = newValue
	dev.Threshold = threshold
	dev.LastUpdated = ts
	dev.UpdateCount++
	if delta < 0 {
		dev.DropCount++
	}
	dev.RecentValues = append(dev.RecentValues, newValue)
	if len(dev.RecentValues) > maxRecentValues {
		dev.RecentValues = dev.RecentValues[len(dev.RecentValues)-maxRecentValues:]
	}
	if newValue < threshold {
		dev.Status = "SUSPECT"
	} else {
		dev.Status = "ACTIVE"
	}
	if _, err := writeDevice(ctx, dev); err != nil {
		return err
	}

	// 5. append the immutable trust event
	ev := models.TrustEvent{
		DocType:      "trustEvent",
		EventID:      ctx.GetStub().GetTxID(),
		DeviceID:     deviceID,
		OldValue:     old,
		NewValue:     newValue,
		Delta:        delta,
		AttackClass:  attackClass,
		Confidence:   confidence,
		ReasonCode:   reasonCode,
		EvidenceHash: hashEvidence(evidencePayload),
		Timestamp:    ts,
		SubmitterMSP: submitterMSP(ctx),
	}
	evBlob, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	ek, err := eventKey(ctx, deviceID, ts)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(ek, evBlob); err != nil {
		return fmt.Errorf("event write failed: %w", err)
	}
	return ctx.GetStub().SetEvent("TrustRecorded", evBlob)
}
