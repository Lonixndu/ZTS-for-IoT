package models

type DeviceAsset struct {
	DocType        string    `json:"docType"`        // always "device"
	DeviceID       string    `json:"deviceId"`       // dev-001
	DeviceType     string    `json:"deviceType"`     // camera, sensor, actuator, gateway, meter, lock
	Criticality    int       `json:"criticality"`    // 1 (low) to 5 (high)
	IdentityHash   string    `json:"identityHash"`   // SHA-256 of the device certificate, hex
	NetworkAddress string    `json:"networkAddress"` // IPv4, used by Member 4 for lookup
	AddressSetAt   string    `json:"addressSetAt"`   // when the address was last set
	Owner          string    `json:"owner"`          // MSP of the organisation that registered it
	TrustValue     float64   `json:"trustValue"`     // 0 to 100
	Threshold      float64   `json:"threshold"`      // per-device limit
	Status         string    `json:"status"`         // ACTIVE or SUSPECT
	RegisteredAt   string    `json:"registeredAt"`
	LastUpdated    string    `json:"lastUpdated"`
	UpdateCount    int       `json:"updateCount"`
	DropCount      int       `json:"dropCount"`
	RecentValues   []float64 `json:"recentValues"` // bounded buffer, newest last, max 20
}

// TrustEvent is one immutable record of a trust change.
// Stored under the composite key trustEvent~<deviceId>~<timestamp> and never modified.
type TrustEvent struct {
	DocType      string  `json:"docType"` // always "trustEvent"
	EventID      string  `json:"eventId"` // the transaction ID
	DeviceID     string  `json:"deviceId"`
	OldValue     float64 `json:"oldValue"`
	NewValue     float64 `json:"newValue"`
	Delta        float64 `json:"delta"`       // negative when trust falls
	AttackClass  string  `json:"attackClass"` // optional label from the AI component
	Confidence   float64 `json:"confidence"`  // 0 to 1
	ReasonCode   string  `json:"reasonCode"`
	EvidenceHash string  `json:"evidenceHash"` // SHA-256 of the evidence, never the evidence itself
	Timestamp    string  `json:"timestamp"`    // fixed-width UTC, sorts correctly as text
	SubmitterMSP string  `json:"submitterMsp"`
}

// AddressLookupResult is what Member 4 receives when looking a device up by IP.
// It deliberately leaves out the identity hash and evidence fingerprints.
type AddressLookupResult struct {
	DeviceID    string  `json:"deviceId"`
	DeviceType  string  `json:"deviceType"`
	Criticality int     `json:"criticality"`
	TrustValue  float64 `json:"trustValue"`
	Status      string  `json:"status"`
	LastUpdated string  `json:"lastUpdated"`
}

// HistoryEntry is one past version of a device record, as returned by
// DeviceContract:GetDeviceHistory.
type HistoryEntry struct {
	TxID      string      `json:"txId"`
	Timestamp string      `json:"timestamp"`
	Record    DeviceAsset `json:"record"`
}
