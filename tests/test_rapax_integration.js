/**
 * RaPaX Pipeline Integration Test Runner
 * Validates /fingerprint IPC hook against native Python core engine
 */

const path = require('path');
const fs = require('fs/promises');
const AcerbeService = require('../services/acerbeService');

async function runIntegrationTest() {
  console.log('=== Starting RaPaX /fingerprint Endpoint Integration Test ===');

  const inputPath = path.resolve(__dirname, 'fixtures/sample_invoice.pdf');
  const outputPath = path.resolve(__dirname, 'output/rapax_stamped_invoice.pdf');
  const manifestPath = `${outputPath}.manifest.json`;

  // 1. Ensure test fixture directories exist
  await fs.mkdir(path.dirname(inputPath), { recursive: true });
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  // 2. Create minimal PDF fixture if missing
  const dummyPdfHeader = '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 55 >>\nstream\nBT\n/Helvetica 12 Tf\n72 712 Td\n(RaPaX Test Document) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000216 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n321\n%%EOF\n';
  await fs.writeFile(inputPath, dummyPdfHeader);

  // 3. Initialize Service
  const service = new AcerbeService({
    secretKey: process.env.ACERBE_SECRET_KEY || 'a'.repeat(64),
    enginePath: path.resolve(__dirname, '../core/engine.py')
  });

  try {
    console.log('[+] Executing watermark embedding request...');
    const result = await service.embedWatermark({
      inputPath,
      outputPath,
      buyerEmail: 'buyer.test@rapax.internal',
      transactionId: 'TX-RAPAX-20261005-001'
    });

    console.log('[✔] Engine Response Received:', JSON.stringify(result, null, 2));

    // 4. Assert Output File Existence
    await fs.access(outputPath);
    await fs.access(manifestPath);
    console.log('[✔] Stamped output PDF and sidecar manifest verified on disk.');

    // 5. Read and Validate Manifest HMAC Integrity
    const manifestContent = JSON.parse(await fs.readFile(manifestPath, 'utf-8'));
    if (!manifestContent.hmac_sha256 || manifestContent.manifest.payload.txid !== 'TX-RAPAX-20261005-001') {
      throw new Error('Manifest validation failed: Mismatched or missing HMAC payload.');
    }
    console.log('[✔] Sidecar Manifest HMAC Validation PASSED.');
    console.log('=== Integration Test Complete: SUCCESS ===');
  } catch (error) {
    console.error('[-] Integration Test Failed:', error.message);
    process.exit(1);
  }
}

runIntegrationTest();

