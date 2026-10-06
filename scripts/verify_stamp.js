const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Zero Trust: Enforce strict environment variables for signing keys
const CONFIG = {
    secretKey: process.env.ACERBE_SIGNING_KEY || (() => { throw new Error('FATAL: ACERBE_SIGNING_KEY environment variable is required.'); })(),
    stampsDir: path.join(__dirname, '..', 'data', 'stamps')
};

function verifyStamp(stampPath) {
    if (!fs.existsSync(stampPath)) {
        console.error(`[✖] Stamp file not found: ${stampPath}`);
        return false;
    }

    try {
        const rawData = fs.readFileSync(stampPath, 'utf8');
        const stamp = JSON.parse(rawData);

        // 1. Verify payload hash integrity
        const recomputedPayloadHash = crypto
            .createHash('sha256')
            .update(JSON.stringify(stamp.payload))
            .digest('hex');

        if (recomputedPayloadHash !== stamp.payloadHash) {
            console.error(`[!] TAMPER DETECTED: Payload hash mismatch for ${stamp.txId}`);
            return false;
        }

        // 2. Reconstruct signed data and verify HMAC signature using timing-safe comparison
        const dataToSign = JSON.stringify({
            txId: stamp.txId,
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
            console.error(`[!] TAMPER DETECTED: Cryptographic signature verification failed for ${stamp.txId}`);
            return false;
        }

        console.log(`[✔] VERIFIED: Stamp integrity valid for TX: ${stamp.txId}`);
        return true;
    } catch (err) {
        console.error(`[!] Verification error for ${stampPath}: ${err.message}`);
        return false;
    }
}

function verifyAllStamps() {
    if (!fs.existsSync(CONFIG.stampsDir)) {
        console.log(`[*] No stamps directory found at ${CONFIG.stampsDir}`);
        return;
    }

    const files = fs.readdirSync(CONFIG.stampsDir).filter(f => f.endsWith('.json'));
    if (files.length === 0) {
        console.log('[*] No forensic stamp artifacts found to verify.');
        return;
    }

    let allValid = true;
    for (const file of files) {
        const stampPath = path.join(CONFIG.stampsDir, file);
        const isValid = verifyStamp(stampPath);
        if (!isValid) allValid = false;
    }

    if (allValid) {
        console.log('[✔] All forensic stamp artifacts successfully verified and untampered.');
    } else {
        console.error('[✖] Integrity check failed for one or more stamps.');
        process.exit(1);
    }
}

if (require.main === module) {
    console.log('[*] Running AcerbE Forensic Stamp Verification Suite...');
    verifyAllStamps();
}
