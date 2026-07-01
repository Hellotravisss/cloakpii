# CLI reference

| Command       | Description                                   |
|---------------|-----------------------------------------------|
| `migrate`     | Run the full migration pipeline               |
| `encrypt`     | Encrypt a single file                         |
| `decrypt`     | Decrypt a single file                         |
| `decrypt-all` | Decrypt a whole migration output tree         |
| `detokenize`  | Reverse `--mode tokenize` back to originals   |
| `scan`        | Scan a directory for PII without migrating    |
| `db-export`   | Export database tables to CSV for migration   |
| `assessment`  | Generate a PIPL Security Assessment template  |
| `init`        | Initialize project configuration              |
| `verify`      | Verify file integrity against a manifest      |
| `status`      | Show status of a previous migration           |
| `profiles`    | List available compliance profiles            |

## `migrate`

```text
cloakpii migrate [OPTIONS]

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

## Examples

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

# Audit mode — per-field confidence + flag fields that need human review
cloakpii scan --source data/ --audit

# Preview — see the exact before→after masking on the first N rows per field
cloakpii scan --source data/ --sample 3

# Restore an output tree, then reverse tokens
cloakpii decrypt-all --input out/encrypted --output restored/
cloakpii detokenize  --input restored/     --output original/
```

## Preview masking (`scan --sample N`)

Before pointing CloakPII at real data, `--sample N` shows the **exact before→after
transform** on the first N values of each field, so you can confirm it masks what
it should and leaves the rest alone:

```text
  ── u.csv ──
    [MASK] email       alice@corp.com    → a***@c******.com
    [MASK] phone       13812345678       → 138******78
    [keep] order_id    10001             (unchanged)
```

Fields marked `MASK` will be transformed; `keep` fields pass through untouched.

## Audit mode (`scan --audit`)

`--audit` adds a per-field confidence breakdown to the scan and, crucially,
flags fields that **need human review** — columns whose *name* suggests PII but
whose values don't match a known pattern (free-text names, unusual formats, the
regex's blind spots). This is where undetected PII tends to hide.

```text
[HIGH] u.csv::email      → email (match 100%)
[HIGH] u.csv::phone      → phone (match 100%)
[LOW ] u.csv::full_name  → name-based (match 0%)   ⚠ review

⚠ 1 field(s) need review (name suggests PII but detector is unsure):
  - u.csv::full_name
```

Confidence levels: **HIGH** (values match a specific pattern), **MED** (name
signals PII and some values match), **LOW** (name signals PII but no values
match — review these).

## Incremental migration & resume

With `--resume`, each processed file (path + SHA-256) is recorded in
`<output>/.migration_state.db`. Later runs skip files whose path and hash are
unchanged; modified files are re-processed. Delete the state file to force a
full re-run; a corrupted state DB is rebuilt automatically.

## Database sources (`db-export`)

Export tables from a database to CSV, then run the normal pipeline on them.
SQLite needs no extra dependency; PostgreSQL and MySQL drivers are optional:

```bash
pip install "cloakpii[postgres]"   # psycopg
pip install "cloakpii[mysql]"      # PyMySQL
```

```bash
# 1. Dump tables to CSV (streamed in batches — constant memory)
cloakpii db-export --url postgresql://user:pw@host/db --output ./dump
cloakpii db-export --url "sqlite:///./app.db"          --output ./dump

# 2. Desensitize + encrypt the dump
cloakpii migrate --source ./dump --output ./safe --compliance-profile pipl --compliance-report
```

URL formats: `sqlite:///path/to.db`, `postgresql://user:pw@host:5432/db`,
`mysql://user:pw@host:3306/db`.

## Docker

```bash
docker run --rm -v $(pwd)/data:/data -v $(pwd)/output:/output \
  -e CLOAKPII_PASSWORD=mypassword \
  cloakpii migrate --source /data --output /output
```
