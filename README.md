# Offshore Data Migrator

A professional, open-source tool designed to help Canadian technology companies prepare for potential regulatory changes around data sovereignty by enabling secure, compliant, and auditable migration of sensitive data and AI assets to offshore jurisdictions — primarily **Singapore**.

## The Problem

Canadian tech companies, especially those working with AI models and large volumes of user data, face growing uncertainty regarding future data localization and sovereignty requirements. Migrating core assets to more favorable jurisdictions in a compliant manner is complex, risky, and time-consuming.

This tool provides a structured, auditable framework to:

- Discover sensitive data and AI model weights
- Apply desensitization and strong encryption
- Plan and execute migration to Singapore (and other jurisdictions)
- Generate compliance-grade audit trails

## Key Features

- **Data Discovery Engine**: Identify PII, credentials, and large model files
- **Automated Desensitization**: Tokenization and redaction of sensitive fields
- **Client-side Encryption**: AES-256-GCM before any data leaves your infrastructure
- **Jurisdiction Templates**: Pre-configured for Singapore (PDPA + MAS guidelines)
- **Compliance Logging**: Detailed audit reports suitable for legal review
- **Dry-run Capability**: Simulate entire migrations before execution
- **Multi-cloud Support**: AWS, GCP, Azure, and custom endpoints

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize project
./offshore-migrator init --project my-ai-company

# 3. Discover sensitive assets
./offshore-migrator discover --path /data --output discovery.json

# 4. Test migration (dry run)
./offshore-migrator migrate --target singapore --dry-run

# 5. Execute real migration when ready
./offshore-migrator migrate --target singapore
```

## Supported Workflows

- **AI Model Migration**: Secure transfer of large model weights
- **User Data Migration**: PII-aware desensitization + encryption
- **Full Infrastructure Move**: Coordinated migration of data + models

## Important Disclaimer

This tool is provided for legitimate business continuity and compliance planning purposes. Always consult with qualified legal counsel in Canada and the destination jurisdiction before transferring data across borders.

## Project Status

This is an early but functional release. Core discovery, desensitization planning, and migration orchestration are implemented. More advanced features (automatic key management, multi-jurisdiction support, advanced AI model analysis) are planned.

## License

MIT License

## Contributing

Contributions are welcome. Please open an issue first to discuss major changes.