---
title: CloakPII — PIPL / PDPA cross-border data compliance in one command
description: >-
  Mask PII, encrypt with AES-256-GCM, and generate PIPL / PDPA / GDPR
  compliance reports for cross-border data transfers — one Python CLI.
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "CloakPII",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Cross-platform (Python 3.10+)",
  "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
  "license": "https://opensource.org/licenses/MIT",
  "description": "A Python CLI that masks or reversibly tokenizes PII, encrypts files with AES-256-GCM, and generates PIPL / PDPA / GDPR compliance reports for cross-border data transfers (China ⇄ Singapore focus).",
  "url": "https://hellotravisss.github.io/cloakpii/",
  "downloadUrl": "https://pypi.org/project/cloakpii/",
  "codeRepository": "https://github.com/Hellotravisss/cloakpii",
  "keywords": "PIPL, PDPA, GDPR, PII masking, data desensitization, cross-border data transfer, AES-256-GCM, tokenization, Python"
}
</script>

# CloakPII

**Moving customer data across borders without leaking PII — or failing a PIPL / PDPA audit — is hard. CloakPII does it in one command.**

If your data leaves China or Singapore, you're on the hook for **PIPL** and **PDPA**: personal data has to be desensitized, the transfer encrypted, and the paperwork filed. Rolling that yourself means stitching together PII detection, a masking scheme, AES encryption, and a compliance checklist — and getting every one of them right.

CloakPII is a single command-line tool that takes a folder of files, **masks (or reversibly tokenizes) the PII** inside, **encrypts every file with AES-256-GCM**, and **generates the PIPL / PDPA compliance report** — so cross-border data is safe to move and you have the audit trail to prove it.

```bash
pip install cloakpii
```

```bash
export CLOAKPII_PASSWORD=...      # keep secrets out of ps / shell history
cloakpii migrate --source ./data --output ./safe \
  --compliance-profile pipl --compliance-report
```

```text
# before                              # after (masked + encrypted)
name,email,phone                      name,email,phone
Wei,wei@corp.cn,138-1234-5678         W***,w***@c******.cn,138-****-**78
```

Masked plaintext lands in `./safe/desensitized/`, AES-256-GCM copies in `./safe/encrypted/`, and a PIPL report (JSON + Markdown) next to them. Restore the whole tree any time with `cloakpii decrypt-all`.

## Why CloakPII

| | **CloakPII** | Microsoft Presidio | Roll-your-own | gpg / openssl |
|---|:---:|:---:|:---:|:---:|
| PII detection (regex + field names) | ✅ | ✅ | ⚠️ DIY | ❌ |
| Chinese IDs **and Chinese column names** | ✅ | ⚠️ partial | ⚠️ DIY | ❌ |
| Irreversible masking | ✅ | ✅ | ⚠️ DIY | ❌ |
| Reversible, **join-preserving** tokenization | ✅ | ❌ | ⚠️ DIY | ❌ |
| Built-in AES-256-GCM encryption | ✅ | ❌ | ⚠️ DIY | ✅ |
| **PIPL / PDPA / GDPR compliance reports** | ✅ | ❌ | ❌ | ❌ |
| Multi-format (CSV/JSON/Excel/Parquet/XML/TSV/SQLite/text) | ✅ | ⚠️ text-first | ⚠️ DIY | ⚠️ opaque blobs |
| One command, folder in → safe folder out | ✅ | ❌ | ❌ | ❌ |

Presidio is a great detection engine, but it stops at detection — you still bolt on encryption and compliance yourself. `gpg` encrypts but never *sees* the PII. CloakPII is the opinionated, end-to-end path for the cross-border-compliance use case.

## What this is — and what it isn't

!!! warning "Read before you rely on it"
    - **Masking (the default) is irreversible** — masked values can't be recovered even after decrypt. Use `--mode tokenize` if you need recoverable, join-preserving data.
    - **Compliance output is documentation, not legal sign-off.** Have counsel review actual cross-border filings.
    - **Detection is not exhaustive** — it's regex + column-name keywords. It does *not* catch bare-digit phone numbers (unless the column name signals PII), 15-digit Chinese IDs, IPv6, free-text names, or PII glued to surrounding letters. Enable the ML backend for names, and spot-check a sample of any new dataset.

## Next steps

- [Installation](installation.md)
- [Mask vs tokenize](modes.md)
- [CLI reference](cli.md)
- [Compliance profiles](compliance.md)
- [Security model](security.md)
