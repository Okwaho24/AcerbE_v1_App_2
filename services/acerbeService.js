/**
 * AcerbE™ Integration Service
 * Lineage: Engine v3.1.0 Subprocess Bridge
 */

const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');

class AcerbeService {
  constructor(config = {}) {
    this.secretKey = config.secretKey || process.env.ACERBE_SECRET_KEY;
    this.pythonPath = config.pythonPath || '/usr/bin/python3';
    this.enginePath = config.enginePath || path.resolve(__dirname, '../core/engine.py');

    if (!this.secretKey || this.secretKey.length < 32) {
      throw new Error('CRITICAL: ACERBE_SECRET_KEY must be set with at least 32 characters.');
    }
  }

  async embedWatermark({ inputPath, outputPath, buyerEmail, transactionId }) {
    await fs.access(inputPath);

    const payload = {
      email: buyerEmail,
      txid: transactionId,
      ts: new Date().toISOString(),
      nonce: crypto.randomBytes(16).toString('hex')
    };

    const args = [
      this.enginePath,
      '--action', 'embed',
      '--input', inputPath,
      '--output', outputPath,
      '--payload', JSON.stringify(payload)
    ];

    const childEnv = {
      ...process.env,
      ACERBE_SECRET_KEY: this.secretKey,
      PYTHONUNBUFFERED: '1'
    };

    return new Promise((resolve, reject) => {
      const child = spawn(this.pythonPath, args, { env: childEnv, shell: false });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
      child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

      child.on('close', (code) => {
        if (code !== 0) {
          return reject(new Error(`AcerbE Engine Failure (Code ${code}): ${stderr}`));
        }

        try {
          resolve(JSON.parse(stdout));
        } catch (err) {
          reject(new Error(`Failed to parse engine output: ${stdout}`));
        }
      });
    });
  }
}

module.exports = AcerbeService;
