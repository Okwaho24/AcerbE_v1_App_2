const fs = require('fs');
const path = require('path');

function renderTemplate(templatePath, context) {
    if (!fs.existsSync(templatePath)) {
        throw new Error(`Template not found at path: ${templatePath}`);
    }

    let content = fs.readFileSync(templatePath, 'utf8');

    // Simple robust mustache-style variable substitution: {{variable_name}}
    return content.replace(/\{\{([\w\.]+)\}\}/g, (match, p1) => {
        const keys = p1.split('.');
        let value = context;
        for (const key of keys) {
            value = value?.[key];
        }
        return value !== undefined ? value : match;
    });
}

function main() {
    console.log("[*] Rendering sample document from Tier 2 Technical matrix...");

    // Target sample: Technical Architecture for acerbe-core in English
    const templatePath = path.join("templates", "tier2_technical", "technical_architecture", "acerbe-core", "en", "template.hbs");
    const outputPath = path.join("templates", "tier2_technical", "technical_architecture", "acerbe-core", "en", "rendered_output.md");

    // Dynamic context variables
    const context = {
        organization: {
            name: "Archer Chain Analytics",
            jurisdiction: "Saskatoon, SK, Canada"
        },
        product: {
            name: "acerbe-core",
            version: "3.1.0",
            runtime: "Python/Node.js Hybrid"
        },
        build: {
            timestamp: new Date().toISOString(),
            manifest_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    };

    // Append dynamic variable placeholders to template if not already present
    let rawTemplate = fs.readFileSync(templatePath, 'utf8');
    if (!rawTemplate.includes("Organization:")) {
        rawTemplate += `
## Deployment Metadata
- **Organization:** {{organization.name}} ({{organization.jurisdiction}})
- **Product:** {{product.name}} v{{product.version}} [{{product.runtime}}]
- **Build Timestamp:** {{build.timestamp}}
- **Manifest Checksum:** \`{{build.manifest_hash}}\`
`;
        fs.writeFileSync(templatePath, rawTemplate);
    }

    try {
        const rendered = renderTemplate(templatePath, context);
        fs.writeFileSync(outputPath, rendered);
        console.log(`[✔] Successfully rendered document to: ${outputPath}`);
        console.log("\n--- Preview Rendered Output ---");
        console.log(rendered);
    } catch (err) {
        console.error(`[✖] Render failed: ${err.message}`);
        process.exit(1);
    }
}

main();
