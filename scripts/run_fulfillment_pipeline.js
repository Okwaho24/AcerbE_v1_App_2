const { spawn } = require('child_process');
const path = require('path');

// Zero Trust: Validate required environment variables before orchestrating
const requiredEnv = ['PAYMENT_RPC_ENDPOINT', 'PAYMENT_API_TOKEN', 'ACERBE_SIGNING_KEY'];
for (const env of requiredEnv) {
    if (!process.env[env]) {
        console.error(`[✖] FATAL: Missing required environment variable: ${env}`);
        process.exit(1);
    }
}

const pollIntervalMs = parseInt(process.env.POLL_INTERVAL_MS || '5000', 10);
const pollerScript = path.join(__dirname, 'payment_poller.js');
const stamperScript = path.join(__dirname, 'crypto_stamper.js');

function runStamper() {
    return new Promise((resolve, reject) => {
        const child = spawn('node', [stamperScript], { stdio: 'inherit' });
        child.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`Stamper exited with code ${code}`));
        });
    });
}

async function startOrchestrator() {
    console.log('[*] Initializing AcerbE Unified Fulfillment & Stamping Orchestrator...');
    
    // Start the payment poller as a long-running background process
    const poller = spawn('node', [pollerScript], { stdio: 'inherit' });

    poller.on('error', (err) => {
        console.error(`[!] Poller process error: ${err.message}`);
    });

    poller.on('close', (code) => {
        console.log(`[!] Poller process exited with code ${code}`);
    });

    // Periodically run the cryptographic stamper to process new log entries
    setInterval(async () => {
        try {
            await runStamper();
        } catch (err) {
            console.error(`[!] Stamping cycle failed: ${err.message}`);
        }
    }, pollIntervalMs);

    // Handle graceful shutdown
    process.on('SIGINT', () => {
        console.log('\n[*] Shutting down orchestrator gracefully...');
        poller.kill('SIGINT');
        process.exit(0);
    });
}

if (require.main === module) {
    startOrchestrator();
}
