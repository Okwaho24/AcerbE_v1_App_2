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

function generateScaffold() {
  console.log("[*] Initializing AcerbE Three-Tier Document Pipeline Scaffold...");

  let totalArtifacts = 0;

  // Tier 1: 10 docs * 7 jurisdictions * 7 languages = 490
  MANIFEST.tier1_legal.forEach(doc => {
    MANIFEST.jurisdictions.forEach(jur => {
      MANIFEST.languages.forEach(lang => {
        const dir = path.join("templates", "tier1_legal", doc, jur, lang);
        fs.mkdirSync(dir, { recursive: true });
        const filePath = path.join(dir, "template.hbs");
        if (!fs.existsSync(filePath)) {
          fs.writeFileSync(filePath, `---
title: "${doc.toUpperCase()} (${jur} - ${lang})"
tier: 1
jurisdiction: "${jur}"
language: "${lang}"
---
# ${doc.replace(/_/g, ' ').toUpperCase()}
Jurisdiction Framework: ${jur}
Language: ${lang}
[Legal terms boilerplate...]
`);
        }
        totalArtifacts++;
      });
    });
  });

  // Tier 2: 7 docs * 2 products * 7 languages = 98
  MANIFEST.tier2_technical.forEach(doc => {
    MANIFEST.products.forEach(prod => {
      MANIFEST.languages.forEach(lang => {
        const dir = path.join("templates", "tier2_technical", doc, prod, lang);
        fs.mkdirSync(dir, { recursive: true });
        const filePath = path.join(dir, "template.hbs");
        if (!fs.existsSync(filePath)) {
          fs.writeFileSync(filePath, `---
title: "${doc.toUpperCase()} for ${prod} (${lang})"
tier: 2
product: "${prod}"
language: "${lang}"
---
# ${doc.replace(/_/g, ' ').toUpperCase()}
Product: ${prod}
Language: ${lang}
[Technical specification content...]
`);
        }
        totalArtifacts++;
      });
    });
  });

  // Tier 3: 2 docs * 7 languages (with global/jurisdiction support) = 14+
  MANIFEST.tier3_hybrid.forEach(doc => {
    MANIFEST.languages.forEach(lang => {
      const dir = path.join("templates", "tier3_hybrid", doc, "global", lang);
      fs.mkdirSync(dir, { recursive: true });
      const filePath = path.join(dir, "template.hbs");
      if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, `---
title: "${doc.toUpperCase()} (Global - ${lang})"
tier: 3
language: "${lang}"
---
# ${doc.replace(/_/g, ' ').toUpperCase()}
Language: ${lang}
[Hybrid escrow/brand terms...]
`);
      }
      totalArtifacts++;
    });
  });

  console.log(`[✔] Pipeline scaffold verified. Total generated/checked templates: ${totalArtifacts}`);
}

generateScaffold();
