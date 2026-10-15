// Command ztiot-cc is the blockchain trust ledger smart contract.
package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/ztiot/ztiot-cc/contracts"
)

func main() {
	cc, err := contractapi.NewChaincode(
		&contracts.DeviceContract{},
		&contracts.TrustContract{},
	)
	if err != nil {
		log.Panicf("error creating ztiot chaincode: %v", err)
	}
	cc.Info.Title = "ztiot trust ledger"
	cc.Info.Version = "1.0.0"
	if err := cc.Start(); err != nil {
		log.Panicf("error starting ztiot chaincode: %v", err)
	}
}
