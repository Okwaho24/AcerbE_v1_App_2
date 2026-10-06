const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// Zero Trust: Enforce strict environment variables for secrets and endpoints
const CONFIG = {
    pollIntervalMs: parseInt(process.env.POLL_INTERVAL_MS || '5000', 10),
    rpcEndpoint: process.env.PAYMENT_RPC_ENDPOINT || (() => { throw new Error('FATAL: PAYMENT_RPC_ENDPOINT environment variable is required.'); })(),
    apiToken: process.env.PAYMENT_API_TOKEN || (() => { throw new Error('FATAL: PAYMENT_API_TOKEN environment variable is required.'); })(),
    stateFile: path.join(__dirname, '..', 'data', 'processed_tx.json')
};

// Ensure local data directory exists for state isolation
function ensureStateDirectory() {
    const dir = path.dirname(CONFIG.stateFile);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    if (!fs.existsSync(CONFIG.stateFile)) {
        fs.writeFileSync(CONFIG.stateFile, JSON.stringify({ processed: [] }, null, 2), { mode: 0o600 });
    }
}

function loadProcessedTransactions() {
    ensureStateDirectory();
    try {
        const data = fs.readFileSync(CONFIG.stateFile, 'utf8');
        return JSON.parse(data).processed || [];
    } catch (err) {
        console.error(`[✖] Failed to read state file: ${err.message}`);
        return [];
    }
}

function saveProcessedTransaction(txId) {
    const processed = loadProcessedTransactions();
    if (!processed.includes(txId)) {
        processed.push(txId);
        fs.writeFileSync(CONFIG.stateFile, JSON.stringify({ processed }, null, 2), { mode: 0o600 });
    }
}

function triggerAcerbEStamping(txId, payload) {
    console.log(`[✔] Payment confirmed for TX: ${txId}. Triggering AcerbE forensic watermark engine...`);
    const fulfillmentLog = path.join(__dirname, '..', 'data', 'fulfillment.log');
    const logEntry = `[${new Date().toISOString()}] TX_CONFIRMED: ${txId} | PAYLOAD: ${JSON.stringify(payload)}\n`;
    fs.appendFileSync(fulfillmentLog, logEntry, { mode: 0o600 });
}

function pollPendingTransactions() {
    console.log(`[*] Polling payment gateway at ${CONFIG.rpcEndpoint}...`);
    
    const url = new URL(CONFIG.rpcEndpoint);
    const client = url.protocol === 'https:' ? https : http;

    const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${CONFIG.apiToken}`,
            'User-Agent': 'AcerbE-POS-Poller/3.1.0'
        }
    };

    const req = client.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            if (res.statusCode !== 200) {
                console.error(`[!] Gateway responded with status code ${res.statusCode}`);
                return;
            }
            try {
                const responseData = JSON.parse(body);
                const pendingTxs = responseData.pending || [];
                const processedTxs = loadProcessedTransactions();

                for (const tx of pendingTxs) {
                    if (tx.status === 'SETTLED' && !processedTxs.includes(tx.id)) {
                        triggerAcerbEStamping(tx.id, tx);
                        saveProcessedTransaction(tx.id);
                    }
                }
            } catch (parseErr) {
                console.error(`[!] Failed to parse polling response: ${parseErr.message}`);
            }
        });
    });

    req.on('error', (err) => {
        console.error(`[!] Network error during poll: ${err.message}`);
    });

    req.end();
}

function startPoller() {
    console.log(`[*] Initializing AcerbE POS Payment Poller (Interval: ${CONFIG.pollIntervalMs}ms)...`);
    setInterval(pollPendingTransactions, CONFIG.pollIntervalMs);
}

if (require.main === module) {
    startPoller();
}
