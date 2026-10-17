'use strict'; //JavaScript reports more mistakes as errors

// Load the settings from gateway/.env into process.env.
// __dirname is gateway/src, so ".." points to gateway/.
require('dotenv').config({ path: require('node:path').join(__dirname, '..', '.env') });
const http = require('node:http'); // built-in web server
const { openContract, contractMessage } = require('./fabric'); // our Fabric connection (fabric.js)

const HOST = process.env.LISTEN_HOST || '127.0.0.1'; // local only: other machines cannot connect
const PORT = Number(process.env.LISTEN_PORT || 3000);
const MAX_BODY = 64 * 1024;  // largest request body: 64 KB
const utf8 = new TextDecoder(); // turns the chaincode's bytes into text

let fabric = null; // set once the connection is open

// send writes a JSON answer with an HTTP status code.
// If obj is already text (JSON from the chaincode), it is sent as it is.
function send(res, code, obj) {
    const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(body);
}

// str turns any value into text, because Fabric passes every chaincode
// argument as text. A missing value becomes "" (empty).
function str(v) {
    if (v === undefined || v === null) return '';
    return String(v);
}

// readJson reads the request body piece by piece and parses it as JSON.
// It returns a Promise, so the caller can "await" it.
function readJson(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        // the body arrives in pieces ("chunks")
        req.on('data', (c) => {
            size += c.length;
            if (size > MAX_BODY) {
                // too big: stop reading so a huge request cannot use up memory
                reject(new Error('body too large'));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        // all pieces received: join them and parse the JSON
        req.on('end', () => {
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                reject(new Error('body must be JSON'));
            }
        });
        req.on('error', reject); // connection problem while reading
    });
}

// errorCode picks the HTTP code for a failed query:
// 404 (not found) for a missing device, 400 (bad request) for anything else.
function errorCode(msg) {
    return /not registered|no device/.test(msg) ? 404 : 400;
}

/** Submit a transaction and wait until it is committed in a block. */
// The four Fabric steps, done one by one so each can be checked:
async function submit(res, fn, args) {
    try {
        // 1. build the proposal (function name + text arguments)
        const proposal = fabric.contract.newProposal(fn, { arguments: args });
        // 2. endorse: the peers run the chaincode and sign the result.
        //    A chaincode error (bad input, access denied) is thrown here.
        const transaction = await proposal.endorse();
        // 3. submit: send the endorsed transaction to the orderer
        const commit = await transaction.submit();
        // 4. wait until the block is committed and check the result
        const status = await commit.getStatus();
        if (!status.successful) {
            send(res, 400, { error: `transaction ${status.transactionId} failed with code ${status.code}` });
            return;
        }
        // success: the change is now on the ledger
        send(res, 200, { status: 'committed', txId: transaction.getTransactionId() });
    } catch (err) {
        const msg = contractMessage(err); // the chaincode's own message, if there is one
        if (msg) {
            send(res, 400, { error: msg });  // the chaincode refused the request
        } else {
            // network or peer problem: details go to the console only, the
            // caller gets a general message (no internal details leak out)
            console.error(`${fn} failed:`, err.message);
            send(res, 502, { error: 'ledger request failed' });
        }
    }
}

/** Evaluate a read-only query on the gateway peer (no block is written). */
async function query(res, fn, arg) {
    try {
        const result = await fabric.contract.evaluateTransaction(fn, arg);
        send(res, 200, utf8.decode(result)); // the chaincode already returns JSON
    } catch (err) {
        const msg = contractMessage(err);
        if (msg) {
            send(res, errorCode(msg), { error: msg }); // 404 or 400
        } else {
            console.error(`${fn} failed:`, err.message);
            send(res, 502, { error: 'ledger request failed' });
        }
    }
}

// Write routes: URL -> function that turns the JSON body into
// [chaincode function name, list of text arguments]. The argument order must
// match the order of the parameters in the Go chaincode.
const routes = {
    '/tx/register': (b) => ['DeviceContract:RegisterDevice',
        [str(b.deviceId), str(b.deviceType), str(b.criticality), str(b.identityHash), str(b.networkAddress)]],
    '/tx/trust': (b) => ['TrustContract:RecordTrustValue',
        [str(b.deviceId), str(b.trustValue), str(b.threshold), str(b.attackClass),
            str(b.reasonCode), str(b.evidence), str(b.confidence)]],
    '/tx/address': (b) => ['DeviceContract:UpdateDeviceAddress', [str(b.deviceId), str(b.newAddress)]],
};

// Read routes: URL start -> chaincode function. The rest of the URL is the
const queries = [
    ['/query/device/', 'DeviceContract:GetDevice'],
    ['/query/by-address/', 'DeviceContract:GetDeviceByAddress'],
    ['/query/history/', 'DeviceContract:GetDeviceHistory'],
    ['/query/events/', 'DeviceContract:GetTrustEvents'],
];

// handle decides what to do with one HTTP request.
async function handle(req, res) {
    // parse the URL; the base "http://localhost" is only needed because
    // req.url is a path like "/query/device/dev-001"
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    // health check: shows which channel, chaincode and organisation are in use
    if (p === '/health') {
        send(res, 200, fabric
            ? { status: 'ok', ledger: 'fabric', channel: fabric.channelName, chaincode: fabric.chaincodeName, msp: fabric.mspId }
            : { status: 'starting', ledger: 'fabric' });
        return;
    }
    // safety check: refuse requests until the Fabric connection is open
    // (main() opens the connection before listening, so this is a safeguard)
    if (!fabric) {
        send(res, 503, { error: 'not connected to Fabric yet' });
        return;
    }
    // write routes
    if (routes[p]) {
        if (req.method !== 'POST') {
            send(res, 405, { error: 'POST only' }); // 405 = method not allowed
            return;
        }
        let body;
        try {
            body = await readJson(req);
        } catch (e) {
            send(res, 400, { error: e.message }); // "body too large" or "body must be JSON"
            return;
        }
        const [fn, args] = routes[p](body);
        await submit(res, fn, args);
        return;
    }
    // read routes
    for (const [prefix, fn] of queries) {
        if (p.startsWith(prefix) && req.method === 'GET') {
            // decodeURIComponent turns "%2D" style codes back into normal characters
            await query(res, fn, decodeURIComponent(p.slice(prefix.length)));
            return;
        }
    }
    send(res, 404, { error: 'unknown endpoint' });
}

// main connects to Fabric, then starts the web server.
async function main() {
    fabric = await openContract(); // wait until the Fabric connection is ready
    const server = http.createServer((req, res) => {
        // any error not caught inside handle() becomes a general 500 answer,
        // so one bad request can never crash the whole connector
        handle(req, res).catch((err) => {
            console.error('unexpected error:', err);
            send(res, 500, { error: 'internal error' });
        });
    });
    server.listen(PORT, HOST, () => {
        console.log(`Fabric connector on http://${HOST}:${PORT} -> channel ${fabric.channelName}, chaincode ${fabric.chaincodeName}, identity ${fabric.mspId}`);
    });

    // clean shut-down on Ctrl+C (SIGINT) or a stop signal (SIGTERM):
    // stop accepting requests and close the Fabric connection
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

// start; if the connection fails (wrong path in .env, network down), print
// the reason and exit with code 1
main().catch((err) => {
    console.error('could not start:', err.message);
    process.exit(1);
});