# CloakPII

[![PyPI](https://img.shields.io/pypi/v/cloakpii.svg)](https://pypi.org/project/cloakpii/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Hellotravisss/cloakpii/actions/workflows/ci.yml/badge.svg)](https://github.com/Hellotravisss/cloakpii/actions/workflows/ci.yml)

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

---

## Why CloakPII

Most teams reach for a general PII library, a separate encryption step, and a hand-written compliance doc. CloakPII collapses all three into one auditable pipeline, with a deliberate focus on **China ⇄ Singapore cross-border transfers**.

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

---

## Two modes: mask (irreversible) or tokenize (reversible)

```bash
# Reversible, join-preserving pseudonyms — masked data stays usable
cloakpii migrate --source ./data --output ./safe --mode tokenize
```

In `--mode tokenize`, every PII value is replaced by a stable token, and **the same input always maps to the same token** (even across separate runs with the same password):

```text
email,city                              email,city
wei@corp.cn,SH        ──tokenize──▶     tkz_p6dk3s7…,SH    ┐ same value →
wei@corp.cn,BJ                          tkz_p6dk3s7…,BJ    ┘ same token (joins work)
li@corp.cn,SH                           tkz_cx5kz36…,SH
```

So you can still **join, GROUP BY, and de-duplicate** the protected data — and recover the originals with the password:

```bash
cloakpii decrypt-all  --input ./safe/encrypted --output ./restored --password "$CLOAKPII_PASSWORD"
cloakpii detokenize   --input ./restored       --output ./original
```

Use **mask** (the default) when the data should never be recoverable; use **tokenize** when downstream systems still need referential integrity.

---

## What this is — and what it isn't

**Use it to** turn a directory of files containing PII into a **desensitized, encrypted** copy that is safe to move across borders (the design focus is **China ⇄ Singapore**, i.e. PIPL + PDPA), together with the paperwork those regimes expect.

Three things to understand before you rely on it:

- **Masking (the default mode) is irreversible.** Masked values (`alice@x.com` → `a***@x******.com`) cannot be recovered — even after you decrypt. If you need the data to stay **usable** (joins, dedup) and recoverable, use `--mode tokenize`.
- **Compliance output is documentation, not legal sign-off.** The `profiles`, `assessment`, and `--compliance-report` features generate checklists and declaration templates to *help* you prepare a filing. They are not legal advice — have counsel review actual cross-border filings.
- **Detection is not exhaustive.** The built-in detector is regex + column-name keywords. By design it does **not** catch: phone numbers written as bare digit runs with no separators (e.g. `13812345678` — masked only if the column name signals PII), old 15-digit Chinese IDs, IPv6 addresses, free-text personal names, or PII glued directly to surrounding letters. Enable the optional ML backend (see [ML_SETUP.md](ML_SETUP.md)) for names and broader coverage, and **spot-check the output on a sample before trusting a new dataset.**

---

## Features

- **Two modes**: irreversible **masking** or reversible, join-preserving **tokenization**
- **8 file formats**: CSV, JSON, Excel, Parquet, XML, TSV, SQLite, plain text
- **11 PII types**: email, phone, SSN, credit card, IP, Chinese ID, passport, bank account, IBAN, MAC address, date of birth
- **5 compliance profiles**: GDPR (EU), PDPA (Singapore), CCPA (California), LGPD (Brazil), PIPL (China)
- **AES-256-GCM encryption** with PBKDF2 key derivation (480k iterations)
- **Parallel processing**, **progress bar**, **resume** interrupted runs
- **Integrity verification** via SHA-256 manifests, **audit trail** (JSON Lines)
- **YAML configuration** with CLI overrides, **gzip compression**, **Docker** support

## Quick Start

```bash
pip install cloakpii
```

Or from source:

```bash
git clone https://github.com/Hellotravisss/cloakpii.git
cd cloakpii
pip install -e .
```

```bash
export CLOAKPII_PASSWORD=mypassword   # used by every command

# Migrate a directory (desensitize + encrypt)
cloakpii migrate --source data/ --output output/

# Preview what would happen (dry run)
cloakpii migrate --source data/ --dry-run

# Encrypt / decrypt a single file
cloakpii encrypt input.csv output.csv.enc
cloakpii decrypt output.csv.enc decrypted.csv

# Restore an entire migration output tree
cloakpii decrypt-all --input output/encrypted --output restored/
```

> **Tip:** prefer `CLOAKPII_PASSWORD` (or `--key-file`) over `--password` — a password on the command line is visible in `ps` and your shell history.

## CLI Reference

| Command       | Description                                   |
|---------------|-----------------------------------------------|
| `migrate`     | Run the full migration pipeline               |
| `encrypt`     | Encrypt a single file                         |
| `decrypt`     | Decrypt a single file                         |
| `decrypt-all` | Decrypt a whole migration output tree         |
| `detokenize`  | Reverse `--mode tokenize` back to originals   |
| `scan`        | Scan a directory for PII without migrating    |
| `assessment`  | Generate a PIPL Security Assessment template  |
| `init`        | Initialize project configuration              |
| `verify`      | Verify file integrity against a manifest      |
| `status`      | Show status of a previous migration           |
| `profiles`    | List available compliance profiles            |

### migrate options

```text
--source DIR            Source directory (default: examples)
--output DIR            Output directory (default: output)
--mode MODE             mask (irreversible, default) | tokenize (reversible)
--target NAME           Target jurisdiction (default: singapore)
--password PW           Encryption password (prefer CLOAKPII_PASSWORD / --key-file)
--key-file FILE         Read the password from a file
--config FILE           Path to YAML config file
--dry-run               Preview without modifying files
--workers N             Number of parallel workers (default: 1)
--batch-size N          Max files to process (0 = all)
--no-progress           Disable progress bar
--compliance-profile P  Validate against profile (gdpr/pdpa/ccpa/lgpd/pipl)
--compliance-report     Generate a detailed compliance report (JSON + Markdown)
--compress              Compress encrypted output with gzip
--resume                Skip already-processed files
--no-manifest           Skip SHA-256 manifest generation
--audit FILE            Path for audit log (JSON Lines)
--skip-patterns PAT...  Glob patterns for files to skip
--verbose               Enable debug logging
--log-file FILE         Write logs to file
```

### Examples

```bash
# Parallel processing with 4 workers
cloakpii migrate --source data/ --output out/ --workers 4

# PIPL compliance check + report
cloakpii migrate --source data/ --compliance-profile pipl --compliance-report

# Resume an interrupted migration
cloakpii migrate --source data/ --output out/ --resume

# With audit log and compression
cloakpii migrate --source data/ --audit out/audit.jsonl --compress

# Scan only — find PII without migrating
cloakpii scan --source data/ --output scan_report.json
```

## Configuration File

Create a `migration.yaml` for reusable settings (CLI arguments override it):

```yaml
source: /path/to/data
output: /path/to/output
target: singapore
compliance_profile: pdpa
workers: 4
show_progress: true
audit_log: true
generate_manifest: true
compress_output: false
skip_patterns:
  - "*.tmp"
  - "test_*"
custom_pii_patterns: []
```

```bash
cloakpii migrate --config migration.yaml
```

> For security, CloakPII will **not** write `password` / `key_file` to a config file — provide the password via `CLOAKPII_PASSWORD`, `--key-file`, or the interactive prompt.

## Supported File Formats

| Format   | Extension              | Notes                                |
|----------|------------------------|--------------------------------------|
| CSV      | `.csv`                 | Comma-separated values               |
| JSON     | `.json`                | Nested structures, numbers included  |
| Excel    | `.xlsx`                | All sheets                           |
| Parquet  | `.parquet`             | Apache Parquet columnar format       |
| XML      | `.xml`                 | Text, tails, and attributes          |
| TSV      | `.tsv`                 | Tab-separated values                 |
| SQLite   | `.db`, `.sqlite`       | All tables (incl. `WITHOUT ROWID`)   |
| Text     | `.txt`, `.log`, `.md`  | Plain text                           |

## Supported PII Types

| PII Type        | Example                    | Masked Output              |
|-----------------|----------------------------|----------------------------|
| Email           | `user@example.com`         | `u***@e******.com`         |
| Phone           | `555-123-4567`             | `555-***-**67`             |
| SSN             | `123-45-6789`              | `***-**-6789`              |
| Credit Card     | `4111111111111111`         | `4111****1111`             |
| IP Address      | `192.168.1.100`            | `192.168.*.*`              |
| Chinese ID      | `110101199001011234`       | `1101***********234`       |
| Passport        | `AB1234567`                | `AB***4567`                |
| Bank Account    | `1234567890123456`         | `1234********3456`         |
| IBAN            | `GB29NWBK60161331926819`   | `GB29****6819`             |
| MAC Address     | `00:1B:44:11:3A:B7`        | `00:1B:**:**:**:B7`        |
| Date of Birth   | `1990-01-15`               | `****-**-15`               |

Column names containing keywords like `name`, `email`, `phone`, `身份证`, `手机号` (English **and** Chinese) are masked even when the value doesn't match a regex.

## Compliance Profiles

```bash
cloakpii profiles
```

| Profile | Jurisdiction | Key Requirements |
|---------|--------------|------------------|
| **PIPL**| China        | Data localization, cross-border security assessment |
| **PDPA**| Singapore    | DPO required, 30-day access requests |
| GDPR    | EU           | Explicit consent, 72h breach notice, right to erasure |
| CCPA    | California    | Right to know / delete / opt-out |
| LGPD    | Brazil        | Legal basis required, ANPD reporting |

With `--compliance-report`, PIPL and PDPA runs emit a `compliance_report_<profile>.json` + `.md` containing a security-assessment checklist and cross-border transfer notes.

## Security

CloakPII is a security tool, so it's built and audited like one:

- **AES-256-GCM** authenticated encryption; random per-file nonce; random per-run salt stored in the wire header.
- **PBKDF2-HMAC-SHA256**, 480,000 iterations.
- **Tokenization** uses AES-GCM-SIV (nonce-misuse-resistant) for stable, reversible pseudonyms.
- Secrets are never written to disk; audit logs and decrypted output are created `0o600`.
- XML parsed with `defusedxml` (XXE-safe); SQLite handlers use parameterized identifiers (no SQL injection); `decrypt-all` caps decompression to resist zip bombs.

See [CHANGELOG.md](CHANGELOG.md) for the full security history. Found an issue? Please open a GitHub issue.

## Docker

```bash
docker run --rm -v $(pwd)/data:/data -v $(pwd)/output:/output \
  -e CLOAKPII_PASSWORD=mypassword \
  cloakpii migrate --source /data --output /output
```

## Incremental Migration & Resume

With `--resume`, each processed file (path + SHA-256) is recorded in `<output>/.migration_state.db`. Later runs skip files whose path and hash are unchanged; modified files are re-processed. Delete the state file to force a full re-run.

## Development

```bash
git clone https://github.com/Hellotravisss/cloakpii.git
cd cloakpii
pip install -e .
pip install pytest ruff
make test     # run the test suite
make lint     # ruff
make build    # build sdist + wheel
```

## License

MIT License. See [LICENSE](LICENSE).

---

<sub>**Keywords:** PIPL compliance tool · PDPA data masking · cross-border data transfer compliance · PII anonymization / desensitization in Python · redact PII in CSV, JSON, Parquet, SQLite · Chinese ID & Chinese column-name masking · AES-256-GCM file encryption · reversible tokenization / pseudonymization · GDPR / CCPA / LGPD data protection.</sub>
