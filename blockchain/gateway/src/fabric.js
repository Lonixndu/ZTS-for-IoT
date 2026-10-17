'use strict'; //JavaScript reports more mistakes as errors

const fs = require('node:fs'); // read the certificate and key files
const path = require('node:path'); // join folder and file names safely
const crypto = require('node:crypto'); // load the private key
const grpc = require('@grpc/grpc-js'); // gRPC: the network protocol Fabric peers use
const { connect, hash, signers } = require('@hyperledger/fabric-gateway'); // official Fabric Gateway client

// required returns a setting from the environment (.env), or stops with a clear message if it is missing. Failing early is better than connecting with a wrong or empty value.
function required(name) {
    const v = process.env[name];
    if (!v) {
        throw new Error(`missing setting ${name} in gateway/.env`);
    }
    return v;
}

// The key file name is not known in advance, so take the first file in the
// keystore folder. Hidden files (starting with ".") are ignored.
function firstFile(dir) {
    const files = fs.readdirSync(dir).filter((f) => !f.startsWith('.'));
    if (files.length === 0) {
        throw new Error(`no file found in ${dir}`);
    }
    return path.join(dir, files[0]);
}

// openContract connects to Fabric and returns the contract object.
// "async" because server.js waits for it with "await".
async function openContract() {
    // 1. read the settings from .env 
    const mspId = required('MSP_ID'); // organisation
    const certPath = required('CERT_PATH'); // the user's certificate (public identity)
    const keyDir = required('KEY_DIR'); // folder holding the user's private key
    const tlsCertPath = required('TLS_CERT_PATH'); // CA certificate used to check the peer's TLS certificate
    const peerEndpoint = required('PEER_ENDPOINT'); // ocalhost:7051
    const peerHostAlias = required('PEER_HOST_ALIAS'); // peer0.org1.example.com
    const channelName = process.env.CHANNEL_NAME || 'ztiotchannel'; // optional, with defaults
    const chaincodeName = process.env.CHAINCODE_NAME || 'ztiot';

    // 2. open one TLS-encrypted gRPC connection to the peer
    // createSsl(tlsRootCert): trust only a peer whose certificate is signed
    // by this CA, so the connector cannot be tricked into talking to a fake peer.
    const tlsRootCert = fs.readFileSync(tlsCertPath);
    const client = new grpc.Client(peerEndpoint, grpc.credentials.createSsl(tlsRootCert), {
        // We connect to "localhost", but the peer's certificate is issued to
        // "peer0.org1.example.com". This tells TLS which name to check.
        'grpc.ssl_target_name_override': peerHostAlias,
    });

    // 3. load the identity that signs every transaction
    const credentials = fs.readFileSync(certPath); // certificate: sent with each transaction
    const privateKey = crypto.createPrivateKey(fs.readFileSync(firstFile(keyDir))); // key: stays on this machine

    // 4. connect to the Fabric Gateway service on the peer
    const gateway = connect({
        client, // the gRPC connection above
        identity: { mspId, credentials }, // who we are
        signer: signers.newPrivateKeySigner(privateKey), // signs each transaction with our key
        hash: hash.sha256, // hash used before signing
        // time limits (milliseconds) so a request never waits for ever:
        evaluateOptions: () => ({ deadline: Date.now() + 5000 }), // queries: 5 s
        endorseOptions: () => ({ deadline: Date.now() + 15000 }), // collecting endorsements: 15 s
        submitOptions: () => ({ deadline: Date.now() + 5000 }), // sending to the orderer: 5 s
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }), // waiting for the block commit: 60 s
    });

    // 5. choose the channel and the chaincode
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);
    // client and gateway are returned so server.js can close them on shut-down
    return { client, gateway, contract, channelName, chaincodeName, mspId };
}

// Returns null when the error did not come from the chaincode (the peer is down). server.js then sends a general error instead.
function contractMessage(err) {
    const details = (err && err.details) || []; // each peer's error details, if any
    for (const d of details) {
        if (d && d.message) {
            // peers prefix the chaincode message with "chaincode response 500, "
            // the regular expression removes everything up to and including that prefix
            const m = d.message.replace(/^.*chaincode response \d+, /, '');
            return m;
        }
    }
    return null;
}

// Make the two functions available to server.js
module.exports = { openContract, contractMessage };