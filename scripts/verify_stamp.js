const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG = {
    secretKey: process.env.ACERBE_SIGNING_KEY || (() => { throw new Error('FATAL: ACERBE_SIGNING_KEY environment variable is required.'); })(),
    stampsDir: path.join(__dirname, '..', 'data', 'stamps')
};

function logNdjson(level, event, data = {}) {
    const record = {
        level,
        timestamp: new Date().toISOString(),
        component: 'stamp_verifier',
        event,
        ...data
    };
    console.log(JSON.stringify(record));
}

function verifyStamp(stampPath) {
    if (!fs.existsSync(stampPath)) {
        logNdjson('ERROR', 'stamp_not_found', { path: stampPath });
        return false;
    }

    try {
        const rawData = fs.readFileSync(stampPath, 'utf8');
        const stamp = JSON.parse(rawData);

        if (!stamp.txId || !stamp.nonce || !stamp.signature || !stamp.payloadHash) {
            logNdjson('ERROR', 'invalid_stamp_schema', { path: stampPath });
            return false;
        }

        // 1. Verify payload hash integrity safely
        const payloadContent = stamp.payload !== undefined ? JSON.stringify(stamp.payload) : "";
        const recomputedPayloadHash = crypto
            .createHash('sha256')
            .update(payloadContent)
            .digest('hex');

        if (recomputedPayloadHash !== stamp.payloadHash) {
            logNdjson('CRITICAL', 'tamper_detected_payload_mismatch', { txId: stamp.txId });
            return false;
        }

        // 2. Reconstruct signed data including nonce and verify HMAC signature
        const dataToSign = JSON.stringify({
            txId: stamp.txId,
            nonce: stamp.nonce,
            payload: stamp.payload,
            timestamp: stamp.timestamp
        });

        const expectedSignature = crypto
            .createHmac('sha256', CONFIG.secretKey)
            .update(dataToSign)
            .digest('hex');

        const sigBuffer = Buffer.from(stamp.signature, 'hex');
        const expectedBuffer = Buffer.from(expectedSignature, 'hex');

        if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
            logNdjson('CRITICAL', 'tamper_detected_signature_mismatch', { txId: stamp.txId });
            return false;
        }

        logNdjson('INFO', 'stamp_verified', { txId: stamp.txId, nonce: stamp.nonce });
        return true;
    } catch (err) {
        logNdjson('ERROR', 'verification_error', { path: stampPath, error: err.message });
        return false;
    }
}

function verifyAllStamps() {
    if (!fs.existsSync(CONFIG.stampsDir)) {
        logNdjson('WARN', 'stamps_dir_missing', { path: CONFIG.stampsDir });
        return;
    }

    const files = fs.readdirSync(CONFIG.stampsDir).filter(f => f.endsWith('.json'));
    if (files.length === 0) {
        logNdjson('INFO', 'no_stamps_found', {});
        return;
    }

    let allValid = true;
    for (const file of files) {
        const stampPath = path.join(CONFIG.stampsDir, file);
        const isValid = verifyStamp(stampPath);
        if (!isValid) allValid = false;
    }

    if (allValid) {
        logNdjson('INFO', 'all_stamps_verified', { count: files.length });
    } else {
        logNdjson('CRITICAL', 'integrity_check_failed', {});
        process.exit(1);
    }
}

if (require.main === module) {
    logNdjson('INFO', 'verifier_started', {});
    verifyAllStamps();
}
