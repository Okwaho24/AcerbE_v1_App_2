const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG = {
    secretKey: process.env.ACERBE_SIGNING_KEY || (() => { throw new Error('FATAL: ACERBE_SIGNING_KEY environment variable is required.'); })(),
    fulfillmentLog: path.join(__dirname, '..', 'data', 'fulfillment.log'),
    stampsDir: path.join(__dirname, '..', 'data', 'stamps')
};

function logNdjson(level, event, data = {}) {
    const record = {
        level,
        timestamp: new Date().toISOString(),
        component: 'crypto_stamper',
        event,
        ...data
    };
    console.log(JSON.stringify(record));
}

function ensureStampsDirectory() {
    if (!fs.existsSync(CONFIG.stampsDir)) {
        fs.mkdirSync(CONFIG.stampsDir, { recursive: true, mode: 0o700 });
    }
}

function generateCryptographicStamp(txId, payload) {
    ensureStampsDirectory();
    
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const payloadHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    
    // Bind txId, nonce, payload, and timestamp into cryptographic signature
    const dataToSign = JSON.stringify({ txId, nonce, payload, timestamp });
    const signature = crypto
        .createHmac('sha256', CONFIG.secretKey)
        .update(dataToSign)
        .digest('hex');

    const stampArtifact = {
        version: "3.2.0",
        engine: "AcerbE-Forensic-Stamper",
        txId,
        nonce,
        timestamp,
        payload,
        payloadHash,
        signature
    };

    const stampPath = path.join(CONFIG.stampsDir, `${txId}.json`);
    const tempPath = `${stampPath}.tmp`;
    
    // Atomic write pattern to prevent partial writes / corruption on crash
    fs.writeFileSync(tempPath, JSON.stringify(stampArtifact, null, 2), { mode: 0o600 });
    fs.renameSync(tempPath, stampPath);
    
    logNdjson('INFO', 'stamp_generated', { txId, nonce, stampPath });
}

function processUnstampedFulfillments() {
    if (!fs.existsSync(CONFIG.fulfillmentLog)) {
        logNdjson('WARN', 'fulfillment_log_missing', { path: CONFIG.fulfillmentLog });
        return;
    }

    const logContent = fs.readFileSync(CONFIG.fulfillmentLog, 'utf8');
    const lines = logContent.split('\n').filter(Boolean);

    lines.forEach(line => {
        try {
            const match = line.match(/TX_CONFIRMED:\s+([^\s]+)\s+\|\s+PAYLOAD:\s+(.+)/);
            if (match) {
                const txId = match[1];
                const payload = JSON.parse(match[2]);
                const stampPath = path.join(CONFIG.stampsDir, `${txId}.json`);

                if (!fs.existsSync(stampPath)) {
                    generateCryptographicStamp(txId, payload);
                }
            }
        } catch (err) {
            logNdjson('ERROR', 'fulfillment_parse_failed', { error: err.message, line });
        }
    });
}

if (require.main === module) {
    logNdjson('INFO', 'stamper_started', {});
    processUnstampedFulfillments();
}
