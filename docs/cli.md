# CLI reference

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

# Restore an output tree, then reverse tokens
cloakpii decrypt-all --input out/encrypted --output restored/
cloakpii detokenize  --input restored/     --output original/
```

## Incremental migration & resume

With `--resume`, each processed file (path + SHA-256) is recorded in
`<output>/.migration_state.db`. Later runs skip files whose path and hash are
unchanged; modified files are re-processed. Delete the state file to force a
full re-run; a corrupted state DB is rebuilt automatically.

## Docker

```bash
docker run --rm -v $(pwd)/data:/data -v $(pwd)/output:/output \
  -e CLOAKPII_PASSWORD=mypassword \
  cloakpii migrate --source /data --output /output
```
