'use strict';
/**
 * Client connector. Exposes the smart contract as a small local HTTP API that
 * only the Python bridge calls. It listens on 127.0.0.1 so it is never
 * reachable from the network.
 *
 * Endpoints (identical to the development mock ledger):
 *   GET  /health
 *   POST /tx/register      {deviceId, deviceType, criticality, identityHash, networkAddress}
 *   POST /tx/trust         {deviceId, trustValue, threshold, attackClass, reasonCode, evidence, confidence}
 *   POST /tx/address       {deviceId, newAddress}
 *   GET  /query/device/:id
 *   GET  /query/by-address/:ip
 *   GET  /query/history/:id
 *   GET  /query/events/:id
 *
 * Run:  npm start
 */
require('dotenv').config({ path: require('node:path').join(__dirname, '..', '.env') });
const http = require('node:http');
const { openContract, contractMessage } = require('./fabric');

const HOST = process.env.LISTEN_HOST || '127.0.0.1';
const PORT = Number(process.env.LISTEN_PORT || 3000);
const MAX_BODY = 64 * 1024;
const utf8 = new TextDecoder();

let fabric = null; // set once the connection is open

function send(res, code, obj) {
    const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(body);
}

function str(v) {
    if (v === undefined || v === null) return '';
    return String(v);
}

function readJson(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (c) => {
            size += c.length;
            if (size > MAX_BODY) {
                reject(new Error('body too large'));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                reject(new Error('body must be JSON'));
            }
        });
        req.on('error', reject);
    });
}

function errorCode(msg) {
    return /not registered|no device/.test(msg) ? 404 : 400;
}

/** Submit a transaction and wait until it is committed in a block. */
async function submit(res, fn, args) {
    try {
        const proposal = fabric.contract.newProposal(fn, { arguments: args });
        const transaction = await proposal.endorse();
        const commit = await transaction.submit();
        const status = await commit.getStatus();
        if (!status.successful) {
            send(res, 400, { error: `transaction ${status.transactionId} failed with code ${status.code}` });
            return;
        }
        send(res, 200, { status: 'committed', txId: transaction.getTransactionId() });
    } catch (err) {
        const msg = contractMessage(err);
        if (msg) {
            send(res, 400, { error: msg });
        } else {
            console.error(`${fn} failed:`, err.message);
            send(res, 502, { error: 'ledger request failed' });
        }
    }
}

/** Evaluate a read-only query on the gateway peer (no block is written). */
async function query(res, fn, arg) {
    try {
        const result = await fabric.contract.evaluateTransaction(fn, arg);
        send(res, 200, utf8.decode(result));
    } catch (err) {
        const msg = contractMessage(err);
        if (msg) {
            send(res, errorCode(msg), { error: msg });
        } else {
            console.error(`${fn} failed:`, err.message);
            send(res, 502, { error: 'ledger request failed' });
        }
    }
}

const routes = {
    '/tx/register': (b) => ['DeviceContract:RegisterDevice',
        [str(b.deviceId), str(b.deviceType), str(b.criticality), str(b.identityHash), str(b.networkAddress)]],
    '/tx/trust': (b) => ['TrustContract:RecordTrustValue',
        [str(b.deviceId), str(b.trustValue), str(b.threshold), str(b.attackClass),
            str(b.reasonCode), str(b.evidence), str(b.confidence)]],
    '/tx/address': (b) => ['DeviceContract:UpdateDeviceAddress', [str(b.deviceId), str(b.newAddress)]],
};

const queries = [
    ['/query/device/', 'DeviceContract:GetDevice'],
    ['/query/by-address/', 'DeviceContract:GetDeviceByAddress'],
    ['/query/history/', 'DeviceContract:GetDeviceHistory'],
    ['/query/events/', 'DeviceContract:GetTrustEvents'],
];

async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    if (p === '/health') {
        send(res, 200, fabric
            ? { status: 'ok', ledger: 'fabric', channel: fabric.channelName, chaincode: fabric.chaincodeName, msp: fabric.mspId }
            : { status: 'starting', ledger: 'fabric' });
        return;
    }
    if (!fabric) {
        send(res, 503, { error: 'not connected to Fabric yet' });
        return;
    }
    if (routes[p]) {
        if (req.method !== 'POST') {
            send(res, 405, { error: 'POST only' });
            return;
        }
        let body;
        try {
            body = await readJson(req);
        } catch (e) {
            send(res, 400, { error: e.message });
            return;
        }
        const [fn, args] = routes[p](body);
        await submit(res, fn, args);
        return;
    }
    for (const [prefix, fn] of queries) {
        if (p.startsWith(prefix) && req.method === 'GET') {
            await query(res, fn, decodeURIComponent(p.slice(prefix.length)));
            return;
        }
    }
    send(res, 404, { error: 'unknown endpoint' });
}

async function main() {
    fabric = await openContract();
    const server = http.createServer((req, res) => {
        handle(req, res).catch((err) => {
            console.error('unexpected error:', err);
            send(res, 500, { error: 'internal error' });
        });
    });
    server.listen(PORT, HOST, () => {
        console.log(`Fabric connector on http://${HOST}:${PORT} -> channel ${fabric.channelName}, chaincode ${fabric.chaincodeName}, identity ${fabric.mspId}`);
    });

    const stop = () => {
        console.log('closing Fabric connection');
        server.close();
        fabric.gateway.close();
        fabric.client.close();
        process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
}

main().catch((err) => {
    console.error('could not start:', err.message);
    process.exit(1);
});
