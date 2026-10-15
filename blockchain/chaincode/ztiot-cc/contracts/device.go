package contracts

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/models"
)

// DeviceContract handles device identity, the network address and history.
type DeviceContract struct {
	contractapi.Contract
}

// RegisterDevice records a new device. Administrator only.
//
// identityHash is the SHA-256 (64 hex characters) of the device certificate.
// networkAddress is the device IPv4 address; it must not be in use by
// another device. Uniqueness is enforced with an address index key that is
// read with GetState, so two concurrent registrations of the same address
// conflict at commit time (MVCC) instead of both succeeding.
func (c *DeviceContract) RegisterDevice(
	ctx contractapi.TransactionContextInterface,
	deviceID string, deviceType string, criticality int,
	identityHash string, networkAddress string,
) error {

	// 1. validate every input before touching state
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	if !allowedDeviceTypes[deviceType] {
		return fmt.Errorf("unsupported device type: %s", deviceType)
	}
	if criticality < 1 || criticality > 5 {
		return fmt.Errorf("criticality must be between 1 and 5")
	}
	if !hexSHA256Pattern.MatchString(identityHash) {
		return fmt.Errorf("identityHash must be 64 lowercase hex characters (SHA-256)")
	}
	if err := validateAddress(networkAddress); err != nil {
		return err
	}

	// 2. authorisation
	if err := requireRole(ctx, roleAdmin); err != nil {
		return err
	}

	// 3. refuse duplicates instead of silently overwriting
	existing, err := ctx.GetStub().GetState(deviceKey(deviceID))
	if err != nil {
		return fmt.Errorf("state read failed: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("device %s is already registered", deviceID)
	}

	// 4. the address must be free
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

	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}

	dev := &models.DeviceAsset{
		DocType:        "device",
		DeviceID:       deviceID,
		DeviceType:     deviceType,
		Criticality:    criticality,
		IdentityHash:   identityHash,
		NetworkAddress: networkAddress,
		AddressSetAt:   ts,
		Owner:          submitterMSP(ctx),
		TrustValue:     100.0,
		Threshold:      defaultThreshold(criticality),
		Status:         "ACTIVE",
		RegisteredAt:   ts,
		LastUpdated:    ts,
		RecentValues:   []float64{100.0},
	}
	blob, err := writeDevice(ctx, dev)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(ak, []byte(deviceID)); err != nil {
		return fmt.Errorf("address index write failed: %w", err)
	}
	return ctx.GetStub().SetEvent("DeviceRegistered", blob)
}

// GetDevice returns the current record of one device.
func (c *DeviceContract) GetDevice(ctx contractapi.TransactionContextInterface, deviceID string) (*models.DeviceAsset, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	return readDevice(ctx, deviceID)
}

// DeviceExists is a cheap check used by scripts before registering.
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
	if err := validateAddress(networkAddress); err != nil {
		return nil, err
	}
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
	dev, err := readDevice(ctx, string(idBytes))
	if err != nil {
		return nil, fmt.Errorf("no device is registered at that address")
	}
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
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	if err := validateAddress(newAddress); err != nil {
		return err
	}
	if err := requireRole(ctx, roleAdmin); err != nil {
		return err
	}

	dev, err := readDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if dev.NetworkAddress == newAddress {
		return fmt.Errorf("device %s already has address %s", deviceID, newAddress)
	}

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

	oldKey, err := addrKey(ctx, dev.NetworkAddress)
	if err != nil {
		return err
	}
	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}

	oldAddress := dev.NetworkAddress
	dev.NetworkAddress = newAddress
	dev.AddressSetAt = ts
	dev.LastUpdated = ts
	if _, err := writeDevice(ctx, dev); err != nil {
		return err
	}
	if err := ctx.GetStub().DelState(oldKey); err != nil {
		return fmt.Errorf("address index delete failed: %w", err)
	}
	if err := ctx.GetStub().PutState(newKey, []byte(deviceID)); err != nil {
		return fmt.Errorf("address index write failed: %w", err)
	}

	payload, _ := json.Marshal(map[string]string{
		"deviceId": deviceID, "oldAddress": oldAddress,
		"newAddress": newAddress, "changedAt": ts,
	})
	return ctx.GetStub().SetEvent("DeviceAddressChanged", payload)
}

// GetDeviceHistory returns every version of a device record, oldest first,
// using the history database the peer maintains automatically.
func (c *DeviceContract) GetDeviceHistory(ctx contractapi.TransactionContextInterface, deviceID string) ([]models.HistoryEntry, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	iter, err := ctx.GetStub().GetHistoryForKey(deviceKey(deviceID))
	if err != nil {
		return nil, fmt.Errorf("history read failed: %w", err)
	}
	defer iter.Close()

	out := []models.HistoryEntry{}
	for iter.HasNext() {
		mod, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if mod.IsDelete {
			continue
		}
		var dev models.DeviceAsset
		if err := json.Unmarshal(mod.Value, &dev); err != nil {
			continue
		}
		if dev.RecentValues == nil {
			dev.RecentValues = []float64{}
		}
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
func (c *DeviceContract) GetTrustEvents(ctx contractapi.TransactionContextInterface, deviceID string) ([]models.TrustEvent, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(eventKeyType, []string{deviceID})
	if err != nil {
		return nil, fmt.Errorf("range read failed: %w", err)
	}
	defer iter.Close()

	out := []models.TrustEvent{}
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
