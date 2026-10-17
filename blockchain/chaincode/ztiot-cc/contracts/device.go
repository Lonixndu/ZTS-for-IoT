package contracts

import (
	"encoding/json" // device records are stored on the ledger as JSON
	"fmt"           // build error messages
	"sort"          // sort the history oldest first
	"time"          // format history timestamps

	"github.com/hyperledger/fabric-contract-api-go/contractapi" // Fabric contract library

	"github.com/ztiot/ztiot-cc/models" // record types: DeviceAsset, TrustEvent, HistoryEntry ...
)

// DeviceContract handles device identity, the network address and history.
// Embedding contractapi.Contract makes every public method below a contract
// function that clients call as "DeviceContract:<MethodName>".
type DeviceContract struct {
	contractapi.Contract
}

// RegisterDevice records a new device. Administrator only.

func (c *DeviceContract) RegisterDevice(
	ctx contractapi.TransactionContextInterface, // gives access to the ledger and the caller's identity
	deviceID string, deviceType string, criticality int,
	identityHash string, networkAddress string,
) error {

	// 1. validate every input before touching state
	if err := validateDeviceID(deviceID); err != nil { // letters, numbers and "-", 3 to 64 characters
		return err
	}
	if !allowedDeviceTypes[deviceType] { // only camera, sensor, actuator, gateway, meter, lock
		return fmt.Errorf("unsupported device type: %s", deviceType)
	}
	if criticality < 1 || criticality > 5 { // how important the device is: 1 low to 5 high
		return fmt.Errorf("criticality must be between 1 and 5")
	}
	if !hexSHA256Pattern.MatchString(identityHash) { // exactly 64 characters 0-9 a-f
		return fmt.Errorf("identityHash must be 64 lowercase hex characters (SHA-256)")
	}
	if err := validateAddress(networkAddress); err != nil { // valid IPv4 in canonical form
		return err
	}

	// 2. authorisation
	// Read the caller's certificate. Anyone who is not an admin is refused.
	if err := requireRole(ctx, roleAdmin); err != nil {
		return err
	}

	// 3. refuse duplicates instead of silently overwriting
	// PutState would replace an existing record, so check first.
	existing, err := ctx.GetStub().GetState(deviceKey(deviceID))
	if err != nil {
		return fmt.Errorf("state read failed: %w", err) // %w keeps the original error inside
	}
	if existing != nil { // nil means the key does not exist yet
		return fmt.Errorf("device %s is already registered", deviceID)
	}

	// 4. the address must be free
	// Look up the address index key for this IP. If it holds a value,
	// another device already uses the IP.
	ak, err := addrKey(ctx, networkAddress)
	if err != nil {
		return err
	}
	holder, err := ctx.GetStub().GetState(ak)
	if err != nil {
		return fmt.Errorf("state read failed: %w", err)
	}
	if holder != nil {
		return fmt.Errorf("network address %s is already assigned to another device", networkAddress)
	}

	// Time of the transaction, set by the client and the same on every peer.
	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}

	// 5. build the new device record
	dev := &models.DeviceAsset{
		DocType:        "device", // marks the record type (useful for CouchDB queries)
		DeviceID:       deviceID,
		DeviceType:     deviceType,
		Criticality:    criticality,
		IdentityHash:   identityHash,
		NetworkAddress: networkAddress,
		AddressSetAt:   ts,
		Owner:          submitterMSP(ctx),             // organisation of the caller
		TrustValue:     100.0,                         // a new device starts fully trusted
		Threshold:      defaultThreshold(criticality), // 5->80, 4->70, 3->60, 2->50, 1->40
		Status:         "ACTIVE",
		RegisteredAt:   ts,
		LastUpdated:    ts,
		RecentValues:   []float64{100.0}, // short list of the latest trust values
	}

	// 6. write the record and the address index, then announce the change
	blob, err := writeDevice(ctx, dev) // JSON-encode and PutState under "DEVICE_<id>"
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(ak, []byte(deviceID)); err != nil { // index: IP -> device ID
		return fmt.Errorf("address index write failed: %w", err)
	}
	// A chaincode event: applications listening to the channel are told a
	// device was registered once the block is committed.
	return ctx.GetStub().SetEvent("DeviceRegistered", blob)
}

// GetDevice returns the current record of one device.
// Read-only: any identity in the channel may call it.
func (c *DeviceContract) GetDevice(ctx contractapi.TransactionContextInterface, deviceID string) (*models.DeviceAsset, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	return readDevice(ctx, deviceID) // error "device ... is not registered" if missing
}

// DeviceExists is a cheap check used by scripts before registering.
// Returns true or false, never an error for a missing device.
func (c *DeviceContract) DeviceExists(ctx contractapi.TransactionContextInterface, deviceID string) (bool, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return false, err
	}
	blob, err := ctx.GetStub().GetState(deviceKey(deviceID))
	if err != nil {
		return false, fmt.Errorf("state read failed: %w", err)
	}
	return blob != nil, nil
}

// GetDeviceByAddress answers Member 4's question: "which device is at this
// IP address, and what type is it?" It reads the address index with a single
// key lookup, so it works on both LevelDB and CouchDB and needs no index file.
func (c *DeviceContract) GetDeviceByAddress(ctx contractapi.TransactionContextInterface, networkAddress string) (*models.AddressLookupResult, error) {
	// Validating the IP also blocks CouchDB query injection, because the
	// address is only ever used as a key, never inside a query string.
	if err := validateAddress(networkAddress); err != nil {
		return nil, err
	}
	// Step 1: IP -> device ID (address index)
	ak, err := addrKey(ctx, networkAddress)
	if err != nil {
		return nil, err
	}
	idBytes, err := ctx.GetStub().GetState(ak)
	if err != nil {
		return nil, fmt.Errorf("state read failed: %w", err)
	}
	if idBytes == nil {
		// same message whether or not the address was ever used,
		// so the lookup cannot be used to map the network
		return nil, fmt.Errorf("no device is registered at that address")
	}
	// Step 2: device ID -> device record
	dev, err := readDevice(ctx, string(idBytes))
	if err != nil {
		return nil, fmt.Errorf("no device is registered at that address")
	}
	// Return only the fields Member 4 needs. The identity hash and owner are
	// left out on purpose (data minimisation).
	return &models.AddressLookupResult{
		DeviceID:    dev.DeviceID,
		DeviceType:  dev.DeviceType,
		Criticality: dev.Criticality,
		TrustValue:  dev.TrustValue,
		Status:      dev.Status,
		LastUpdated: dev.LastUpdated,
	}, nil
}

// UpdateDeviceAddress moves a device to a new IP address. Administrator only.
// The old address is released and the change is kept in the device history.
func (c *DeviceContract) UpdateDeviceAddress(ctx contractapi.TransactionContextInterface, deviceID string, newAddress string) error {
	// validate inputs, then check the caller is an admin
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	if err := validateAddress(newAddress); err != nil {
		return err
	}
	if err := requireRole(ctx, roleAdmin); err != nil {
		return err
	}

	// the device must exist and the address must actually change
	dev, err := readDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if dev.NetworkAddress == newAddress {
		return fmt.Errorf("device %s already has address %s", deviceID, newAddress)
	}

	// the new address must not belong to another device
	newKey, err := addrKey(ctx, newAddress)
	if err != nil {
		return err
	}
	holder, err := ctx.GetStub().GetState(newKey)
	if err != nil {
		return fmt.Errorf("state read failed: %w", err)
	}
	if holder != nil {
		return fmt.Errorf("network address %s is already assigned to another device", newAddress)
	}

	// index key of the old address, which will be released
	oldKey, err := addrKey(ctx, dev.NetworkAddress)
	if err != nil {
		return err
	}
	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}

	// update the device record (the old version stays in the ledger history)
	oldAddress := dev.NetworkAddress
	dev.NetworkAddress = newAddress
	dev.AddressSetAt = ts
	dev.LastUpdated = ts
	if _, err := writeDevice(ctx, dev); err != nil {
		return err
	}
	// move the index: delete old IP -> device, add new IP -> device.
	// The old IP is now free for another device.
	if err := ctx.GetStub().DelState(oldKey); err != nil {
		return fmt.Errorf("address index delete failed: %w", err)
	}
	if err := ctx.GetStub().PutState(newKey, []byte(deviceID)); err != nil {
		return fmt.Errorf("address index write failed: %w", err)
	}

	// announce the change with the old and new address
	payload, _ := json.Marshal(map[string]string{
		"deviceId": deviceID, "oldAddress": oldAddress,
		"newAddress": newAddress, "changedAt": ts,
	})
	return ctx.GetStub().SetEvent("DeviceAddressChanged", payload)
}

// GetDeviceHistory returns every version of a device record, oldest first,
// using the history database the peer maintains automatically.
// This is the tamper-proof audit trail: each version has the transaction ID
// and the time it was written, and old versions cannot be changed.
func (c *DeviceContract) GetDeviceHistory(ctx contractapi.TransactionContextInterface, deviceID string) ([]models.HistoryEntry, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	// an iterator over every value this key has ever had
	iter, err := ctx.GetStub().GetHistoryForKey(deviceKey(deviceID))
	if err != nil {
		return nil, fmt.Errorf("history read failed: %w", err)
	}
	defer iter.Close() // always close the iterator when the function ends

	out := []models.HistoryEntry{} // empty list, not nil, so the answer is [] and not null
	for iter.HasNext() {
		mod, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if mod.IsDelete { // skip delete markers
			continue
		}
		var dev models.DeviceAsset
		if err := json.Unmarshal(mod.Value, &dev); err != nil {
			continue // skip a version that cannot be read
		}
		if dev.RecentValues == nil {
			dev.RecentValues = []float64{}
		}
		// convert the peer's timestamp to the same text format used everywhere else
		ts := ""
		if mod.Timestamp != nil {
			ts = time.Unix(mod.Timestamp.Seconds, int64(mod.Timestamp.Nanos)).UTC().Format(tsLayout)
		}
		out = append(out, models.HistoryEntry{TxID: mod.TxId, Timestamp: ts, Record: dev})
	}
	// sort oldest first so the timeline reads forward; fixed-width
	// timestamps sort correctly as text, and this does not depend on the
	// order the peer happens to return
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
	return out, nil
}

// GetTrustEvents returns every trust change for one device, oldest first.
// Each event is stored under a composite key (trustEvent, device ID, time).
// A partial key search with only the device ID returns all its events,
// already in time order because the keys are sorted.
func (c *DeviceContract) GetTrustEvents(ctx contractapi.TransactionContextInterface, deviceID string) ([]models.TrustEvent, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(eventKeyType, []string{deviceID})
	if err != nil {
		return nil, fmt.Errorf("range read failed: %w", err)
	}
	defer iter.Close()

	out := []models.TrustEvent{} // [] instead of null when there are no events
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var ev models.TrustEvent
		if err := json.Unmarshal(kv.Value, &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}
