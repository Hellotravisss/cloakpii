---
title: CloakPII FAQ — PIPL/PDPA PII masking, encryption, compliance
description: Answers to common questions about masking PII, encrypting data, and generating PIPL/PDPA/GDPR compliance reports with CloakPII.
---

# Frequently asked questions

## How do I mask PII for a PIPL cross-border data transfer?

Run `cloakpii migrate --source ./data --output ./safe --compliance-profile pipl --compliance-report`. CloakPII detects and masks the personal data in your files, encrypts every file with AES-256-GCM, and generates a PIPL compliance report (JSON + Markdown) including a security-assessment checklist and the cross-border transfer record count.

## How do I desensitize data moving from China to Singapore?

Use CloakPII with the `pipl` or `pdpa` compliance profile — it is built specifically for the China ⇄ Singapore (PIPL + PDPA) cross-border case. It masks or tokenizes the PII, encrypts the output, and produces the paperwork both regimes expect.

## What is a Python tool to mask or redact PII in CSV, JSON, Parquet, or SQLite?

CloakPII is an open-source Python CLI that redacts PII across 8 formats — CSV, JSON, Excel, Parquet, XML, TSV, SQLite, and plain text — including PII stored as numbers. Install it with `pip install cloakpii`.

## How is CloakPII different from Microsoft Presidio?

CloakPII bundles PII detection **plus** AES-256-GCM encryption **plus** PIPL/PDPA/GDPR compliance reports in a single command, whereas Presidio is a detection engine that leaves encryption and compliance to you. CloakPII also handles Chinese national IDs and Chinese column names out of the box and offers reversible, join-preserving tokenization.

## Can I mask data but keep it usable for joins and deduplication?

Yes — use `--mode tokenize`. Each PII value becomes a stable token, so the same input always maps to the same token (joins, GROUP BY, and dedup still work), and you can recover the originals later with the password.

## Does CloakPII encrypt the data as well as mask it?

Yes. Every output file is encrypted with AES-256-GCM (PBKDF2 key derivation), and large files use a chunked streaming format so they encrypt in constant memory. Restore the whole tree with `cloakpii decrypt-all`.

## Can CloakPII read directly from a database?

Yes — `cloakpii db-export --url postgresql://user:pw@host/db --output ./dump` exports tables to CSV for the pipeline. SQLite works with no extra dependency; PostgreSQL and MySQL drivers are optional extras (`pip install "cloakpii[postgres]"` or `"cloakpii[mysql]"`).

## Which compliance regimes does CloakPII support?

PIPL (China) and PDPA (Singapore) are the primary focus, with GDPR (EU), CCPA (California), and LGPD (Brazil) profiles also available. Run `cloakpii profiles` to list them.

## Is CloakPII free?

Yes, CloakPII is open source under the MIT license and free to use. The source is on [GitHub](https://github.com/Hellotravisss/cloakpii) and it is published on [PyPI](https://pypi.org/project/cloakpii/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type":"Question","name":"How do I mask PII for a PIPL cross-border data transfer?","acceptedAnswer":{"@type":"Answer","text":"Run cloakpii migrate --source ./data --output ./safe --compliance-profile pipl --compliance-report. CloakPII detects and masks the personal data, encrypts every file with AES-256-GCM, and generates a PIPL compliance report."}},
    {"@type":"Question","name":"How do I desensitize data moving from China to Singapore?","acceptedAnswer":{"@type":"Answer","text":"Use CloakPII with the pipl or pdpa compliance profile — it is built for the China to Singapore (PIPL + PDPA) cross-border case. It masks or tokenizes the PII, encrypts the output, and produces the required paperwork."}},
    {"@type":"Question","name":"What is a Python tool to mask or redact PII in CSV, JSON, Parquet, or SQLite?","acceptedAnswer":{"@type":"Answer","text":"CloakPII is an open-source Python CLI that redacts PII across CSV, JSON, Excel, Parquet, XML, TSV, SQLite, and plain text, including PII stored as numbers. Install it with pip install cloakpii."}},
    {"@type":"Question","name":"How is CloakPII different from Microsoft Presidio?","acceptedAnswer":{"@type":"Answer","text":"CloakPII bundles PII detection plus AES-256-GCM encryption plus PIPL/PDPA/GDPR compliance reports in one command, whereas Presidio is a detection engine that leaves encryption and compliance to you. CloakPII also handles Chinese national IDs and column names and offers reversible tokenization."}},
    {"@type":"Question","name":"Can I mask data but keep it usable for joins and deduplication?","acceptedAnswer":{"@type":"Answer","text":"Yes, use --mode tokenize. Each PII value becomes a stable token so the same input always maps to the same token, keeping joins and dedup working, and you can recover the originals with the password."}},
    {"@type":"Question","name":"Does CloakPII encrypt the data as well as mask it?","acceptedAnswer":{"@type":"Answer","text":"Yes. Every output file is encrypted with AES-256-GCM using PBKDF2 key derivation, and large files use a chunked streaming format for constant memory."}},
    {"@type":"Question","name":"Can CloakPII read directly from a database?","acceptedAnswer":{"@type":"Answer","text":"Yes, cloakpii db-export exports PostgreSQL, MySQL, or SQLite tables to CSV for the pipeline. SQLite needs no extra dependency; Postgres and MySQL are optional extras."}},
    {"@type":"Question","name":"Which compliance regimes does CloakPII support?","acceptedAnswer":{"@type":"Answer","text":"PIPL (China) and PDPA (Singapore) are the focus, with GDPR, CCPA, and LGPD also available."}},
    {"@type":"Question","name":"Is CloakPII free?","acceptedAnswer":{"@type":"Answer","text":"Yes, CloakPII is open source under the MIT license and free to use, with source on GitHub and releases on PyPI."}}
  ]
}
</script>
