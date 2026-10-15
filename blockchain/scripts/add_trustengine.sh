#!/usr/bin/env bash
# Create the "trustengine1" identity in Org1 with the certificate attribute
# role=trustengine.  This is the identity the trust engine (Member 1) writes
# with: it may record trust values but may NOT register devices.
#
# Run after:  ./network.sh up createChannel -c ztiotchannel -ca -s couchdb
set -euo pipefail

FABRIC_HOME="${FABRIC_HOME:-$HOME/fabric/fabric-samples}"
TN="$FABRIC_HOME/test-network"
export PATH="$FABRIC_HOME/bin:$PATH"

NAME="${1:-trustengine1}"
SECRET="${2:-$(openssl rand -hex 12)}"
ORG1="$TN/organizations/peerOrganizations/org1.example.com"
CA_TLS="$TN/organizations/fabric-ca/org1/ca-cert.pem"
USER_MSP="$ORG1/users/$NAME@org1.example.com/msp"

# the registrar (CA admin) was enrolled into this folder by network.sh
export FABRIC_CA_CLIENT_HOME="$ORG1"

echo "registering $NAME ..."
fabric-ca-client register --caname ca-org1 \
    --id.name "$NAME" --id.secret "$SECRET" --id.type client \
    --id.attrs 'role=trustengine:ecert' \
    --tls.certfiles "$CA_TLS"

echo "enrolling $NAME ..."
fabric-ca-client enroll -u "https://$NAME:$SECRET@localhost:7054" --caname ca-org1 \
    -M "$USER_MSP" --tls.certfiles "$CA_TLS"

# NodeOU settings so the peer recognises the identity as a client
cp "$ORG1/msp/config.yaml" "$USER_MSP/config.yaml"
chmod 600 "$USER_MSP"/keystore/*

echo
echo "done. certificate: $USER_MSP/signcerts/cert.pem"
echo "check the attribute is inside the certificate:"
openssl x509 -in "$USER_MSP/signcerts/cert.pem" -noout -text | grep -A1 "1.2.3.4.5.6.7.8.1" || true
