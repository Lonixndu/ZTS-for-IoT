package main // "main" = this package builds a program you can run

import (
	"log" // print an error message before stopping

	"github.com/hyperledger/fabric-contract-api-go/contractapi" // Fabric contract library

	"github.com/ztiot/ztiot-cc/contracts" // our two contracts (contracts/device.go and contracts/trust.go)
)

func main() {
	// Build one chaincode that contains both contracts.
	cc, err := contractapi.NewChaincode(
		&contracts.DeviceContract{},
		&contracts.TrustContract{},
	)
	if err != nil {
		// Stop at once: a broken chaincode must never start.
		log.Panicf("error creating ztiot chaincode: %v", err)
	}

	// Name and version shown in the chaincode metadata
	cc.Info.Title = "ztiot trust ledger"
	cc.Info.Version = "1.0.0"

	// Connect to the peer and wait for transactions. Start only returns
	if err := cc.Start(); err != nil {
		log.Panicf("error starting ztiot chaincode: %v", err)
	}
}
