const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG = {
    secretKey: process.env.ACERBE_SIGNING_KEY || (() => { throw new Error('FATAL: ACERBE_SIGNING_KEY environment variable is required.'); })(),
    fulfillmentLog: path.join(__dirname, '..', 'data', 'fulfillment.log'),
    stampsDir: path.join(__dirname, '..', 'data', 'stamps')
};

function ensureStampsDirectory() {
    if (!fs.existsSync(CONFIG.stampsDir)) {
        fs.mkdirSync(CONFIG.stampsDir, { recursive: true, mode: 0o700 });
    }
}

function generateCryptographicStamp(txId, payload) {
    ensureStampsDirectory();
    
    const timestamp = new Date().toISOString();
    const payloadHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    
    const dataToSign = JSON.stringify({ txId, payload, timestamp });
    const signature = crypto
        .createHmac('sha256', CONFIG.secretKey)
        .update(dataToSign)
        .digest('hex');

    const stampArtifact = {
        version: "3.1.0",
        engine: "AcerbE-Forensic-Stamper",
        txId,
        timestamp,
        payload,
        payloadHash,
        signature
    };

    const stampPath = path.join(CONFIG.stampsDir, `${txId}.json`);
    fs.writeFileSync(stampPath, JSON.stringify(stampArtifact, null, 2), { mode: 0o600 });
    console.log(`[✔] Generated cryptographic forensic stamp for TX: ${txId} -> ${stampPath}`);
}

function processUnstampedFulfillments() {
    if (!fs.existsSync(CONFIG.fulfillmentLog)) {
        console.log(`[*] No fulfillment log found at ${CONFIG.fulfillmentLog}`);
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

                // Regenerate if missing or outdated
                generateCryptographicStamp(txId, payload);
            }
        } catch (err) {
            console.error(`[!] Failed to process fulfillment line: ${err.message}`);
        }
    });
}

if (require.main === module) {
    console.log("[*] Running AcerbE Cryptographic Stamping Pipeline...");
    processUnstampedFulfillments();
}
