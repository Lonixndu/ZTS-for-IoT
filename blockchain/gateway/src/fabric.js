'use strict';
/**
 * Fabric connection: loads the client identity, opens one gRPC connection to
 * the gateway peer and returns the smart contract object.
 *
 * All settings come from gateway/.env (see .env.example). Nothing secret is
 * written in this file.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const grpc = require('@grpc/grpc-js');
const { connect, hash, signers } = require('@hyperledger/fabric-gateway');

function required(name) {
    const v = process.env[name];
    if (!v) {
        throw new Error(`missing setting ${name} in gateway/.env`);
    }
    return v;
}

/** Fabric CA names the private key "<hash>_sk"; cryptogen names it "priv_sk". */
function firstFile(dir) {
    const files = fs.readdirSync(dir).filter((f) => !f.startsWith('.'));
    if (files.length === 0) {
        throw new Error(`no file found in ${dir}`);
    }
    return path.join(dir, files[0]);
}

async function openContract() {
    const mspId = required('MSP_ID');
    const certPath = required('CERT_PATH');
    const keyDir = required('KEY_DIR');
    const tlsCertPath = required('TLS_CERT_PATH');
    const peerEndpoint = required('PEER_ENDPOINT');
    const peerHostAlias = required('PEER_HOST_ALIAS');
    const channelName = process.env.CHANNEL_NAME || 'ztiotchannel';
    const chaincodeName = process.env.CHAINCODE_NAME || 'ztiot';

    const tlsRootCert = fs.readFileSync(tlsCertPath);
    const client = new grpc.Client(peerEndpoint, grpc.credentials.createSsl(tlsRootCert), {
        'grpc.ssl_target_name_override': peerHostAlias,
    });

    const credentials = fs.readFileSync(certPath);
    const privateKey = crypto.createPrivateKey(fs.readFileSync(firstFile(keyDir)));

    const gateway = connect({
        client,
        identity: { mspId, credentials },
        signer: signers.newPrivateKeySigner(privateKey),
        hash: hash.sha256,
        evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
        endorseOptions: () => ({ deadline: Date.now() + 15000 }),
        submitOptions: () => ({ deadline: Date.now() + 5000 }),
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });

    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);
    return { client, gateway, contract, channelName, chaincodeName, mspId };
}

/**
 * Turn a Fabric error into the short message the chaincode returned, for
 * example "device dev-001 is not registered". Internal gRPC detail is not
 * passed back to callers.
 */
function contractMessage(err) {
    const details = (err && err.details) || [];
    for (const d of details) {
        if (d && d.message) {
            // peers prefix the chaincode message with "chaincode response 500, "
            const m = d.message.replace(/^.*chaincode response \d+, /, '');
            return m;
        }
    }
    return null;
}

module.exports = { openContract, contractMessage };
