#!/usr/bin/env bash
# Load the peer CLI settings for Org1 (admin).  Use it with "source":
#     source ~/ztiot/scripts/fabric_env.sh
# Change FABRIC_HOME if you installed fabric-samples somewhere else.

export FABRIC_HOME="${FABRIC_HOME:-$HOME/fabric/fabric-samples}"
export TN="$FABRIC_HOME/test-network"
export PATH="$FABRIC_HOME/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC_HOME/config"

export CHANNEL=ztiotchannel
export CC_NAME=ztiot

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS=localhost:7051

export ORDERER_CA="$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
export ORG1_TLS="$CORE_PEER_TLS_ROOTCERT_FILE"
export ORG2_TLS="$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

# invoke a transaction on both peers (the default policy needs both orgs)
#   cc_invoke '{"function":"DeviceContract:GetDevice","Args":["dev-001"]}'
cc_invoke() {
    peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
        --tls --cafile "$ORDERER_CA" -C "$CHANNEL" -n "$CC_NAME" \
        --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_TLS" \
        --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_TLS" \
        --waitForEvent -c "$1"
}

# read-only query on the Org1 peer
#   cc_query '{"Args":["DeviceContract:GetDevice","dev-001"]}'
cc_query() {
    peer chaincode query -C "$CHANNEL" -n "$CC_NAME" -c "$1"
}

echo "Org1 admin settings loaded (channel $CHANNEL, chaincode $CC_NAME)"
