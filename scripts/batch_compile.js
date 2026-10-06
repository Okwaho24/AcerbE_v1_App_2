const fs = require('fs');
const path = require('path');

const MANIFEST = {
  version: "3.1.0",
  languages: ["en", "fr", "de", "es", "ja", "zh", "ar"],
  jurisdictions: ["CA", "US", "EU", "UK", "AU", "SG", "JP"],
  tier1_legal: [
    "eula", "tos", "privacy_policy", "compliance_disclosure",
    "risk_disclosure", "ip_statement", "license_template",
    "whitelabel_license", "reseller_agreement", "delivery_terms"
  ],
  tier2_technical: [
    "security_model", "technical_architecture", "installation_guide",
    "user_manual", "emergency_procedures", "troubleshooting_guide", "sbom"
  ],
  tier3_hybrid: [
    "source_escrow_terms", "brand_guidelines"
  ],
  products: ["acerbe-core", "acerbe-api"]
};

function batchCompile() {
  console.log("[*] Starting Batch Compilation of 602 Document Pipeline Templates...");
  let compiledCount = 0;
  let errorCount = 0;

  const timestamp = new Date().toISOString();

  // 1. Compile Tier 1 Legal Matrix (490 templates)
  MANIFEST.tier1_legal.forEach(doc => {
    MANIFEST.jurisdictions.forEach(jur => {
      MANIFEST.languages.forEach(lang => {
        const dir = path.join("templates", "tier1_legal", doc, jur, lang);
        const templatePath = path.join(dir, "template.hbs");
        const outputPath = path.join(dir, "compiled.md");
        try {
          if (fs.existsSync(templatePath)) {
            let content = fs.readFileSync(templatePath, 'utf8');
            content += `\n\n---\n*Build Context: Tier 1 Legal | Jurisdiction: ${jur} | Language: ${lang} | Generated: ${timestamp}*`;
            fs.writeFileSync(outputPath, content);
            compiledCount++;
          } else {
            errorCount++;
          }
        } catch (err) {
          errorCount++;
        }
      });
    });
  });

  // 2. Compile Tier 2 Technical Matrix (98 templates)
  MANIFEST.tier2_technical.forEach(doc => {
    MANIFEST.products.forEach(prod => {
      MANIFEST.languages.forEach(lang => {
        const dir = path.join("templates", "tier2_technical", doc, prod, lang);
        const templatePath = path.join(dir, "template.hbs");
        const outputPath = path.join(dir, "compiled.md");
        try {
          if (fs.existsSync(templatePath)) {
            let content = fs.readFileSync(templatePath, 'utf8');
            content += `\n\n---\n*Build Context: Tier 2 Technical | Product: ${prod} | Language: ${lang} | Generated: ${timestamp}*`;
            fs.writeFileSync(outputPath, content);
            compiledCount++;
          } else {
            errorCount++;
          }
        } catch (err) {
          errorCount++;
        }
      });
    });
  });

  // 3. Compile Tier 3 Hybrid Matrix (14 templates)
  MANIFEST.tier3_hybrid.forEach(doc => {
    MANIFEST.languages.forEach(lang => {
      const dir = path.join("templates", "tier3_hybrid", doc, "global", lang);
      const templatePath = path.join(dir, "template.hbs");
      const outputPath = path.join(dir, "compiled.md");
      try {
        if (fs.existsSync(templatePath)) {
          let content = fs.readFileSync(templatePath, 'utf8');
          content += `\n\n---\n*Build Context: Tier 3 Hybrid | Scope: Global | Language: ${lang} | Generated: ${timestamp}*`;
          fs.writeFileSync(outputPath, content);
          compiledCount++;
        } else {
          errorCount++;
        }
      } catch (err) {
        errorCount++;
      }
    });
  });

  console.log(`[✔] Batch compilation complete.`);
  console.log(`    - Successfully compiled artifacts: ${compiledCount}`);
  console.log(`    - Encountered errors/missing files: ${errorCount}`);
}

batchCompile();
