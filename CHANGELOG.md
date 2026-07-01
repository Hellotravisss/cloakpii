# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-06-30

### Added
- **`reidentify` command** — resolve specific tokens (`--tokens tkz_a,tkz_b`) or a
  whole returned file (`--input results.csv --output originals.csv`) back to
  originals with the password, without detokenizing an entire tree. Completes the
  tokenize round-trip: send tokenized data offshore → get results back carrying
  `tkz_...` tokens → re-identify just the rows you need. Same value → same token,
  so joins on the tokenized data still hold.

## [1.7.0] - 2026-06-30

### Added
- **Masking preview** — `cloakpii scan --sample N` shows the exact before→after
  transform on the first N values of each field, so you can confirm what will be
  masked (and what won't) before running on real data. Included in the `--output`
  JSON report.
- **Per-dataset detection overrides** on `migrate`, so you can correct detection
  without editing YAML:
  - `--force-mask COL` — always mask a column (even if not auto-detected)
  - `--never-mask COL` — leave a column untouched
  - `--drop-field COL` — remove a column entirely
  - `--pattern NAME=REGEX` — add a custom PII pattern (repeatable)
  CLI overrides layer on top of any config-file `field_policies`.

## [1.6.0] - 2026-06-24

Outcome of a multi-agent audit of the codebase (security, correctness, detection,
tests, docs, CI).

### Security
- **Streaming encryption: nonce reuse fixed.** v1.5.0 combined one run-wide AES
  key with only a 64-bit random per-file nonce prefix; a birthday collision
  reused (key, nonce) across large files (catastrophic for AES-GCM). Each file
  now derives an independent key via HKDF-SHA256(run_key, per-file 128-bit salt)
  with a 96-bit counter nonce. **The streaming format changed (magic
  CPIISTM1→CPIISTM2); re-encrypt any ≥50 MB files from v1.5.0.** The legacy
  single-shot format is unchanged.
- **Streaming decrypt no longer leaves partial plaintext.** A truncated stream
  used to leave already-decrypted (world-readable-by-umask) plaintext on disk.
  Decryption now writes to a temp file and atomically promotes it only after the
  final chunk authenticates.
- CI now runs `bandit` (static) and `pip-audit`, plus `build` + `twine check`, on
  every PR; added Dependabot.

### Fixed
- **Date of birth was never actually masked** despite being advertised — the
  regex/masker existed but was never wired into detection. Now masked.
- **MySQL URLs**: username/password/database are percent-decoded, so credentials
  containing `@ : /` authenticate correctly (matching the Postgres path).
- **XML per-field policies** now work on namespaced tags/attributes (a `drop`
  policy on a namespaced element previously leaked it).

### Detection (low false-positive)
- Bare-digit mainland-China mobiles (`13812345678`), 15-digit legacy Chinese IDs,
  and IPv6 addresses are now detected. More Chinese/English column-name keywords.

### Internal
- Single canonical pattern list is now the one source of truth for detection
  order/membership (the drift that hid the DOB bug). CSV/TSV share one code path;
  removed dead code; deduped config pattern registration. +17 regression tests.

## [1.5.0] - 2026-06-20

### Added
- **Per-field policies.** `field_policies` in `migration.yaml` pins a field to an
  explicit action — `mask`, `tokenize`, `drop` (remove the column/key/element), or
  `keep` (leave untouched) — overriding the global mode and the auto-detector.
  Works across all 8 formats.
- **Detection confidence + audit mode.** `cloakpii scan --audit` reports a
  per-field HIGH/MED/LOW confidence breakdown and flags fields that **need
  review** — columns whose name suggests PII but whose values don't match a known
  pattern (free-text names, odd formats — the detector's blind spots).
- **Richer compliance reports.** `--compliance-report` now includes a real
  data-processing summary (files, records, PII values, data categories) and, for
  PIPL, computes the 100k-record threshold from the actual row count.
- **Streaming encryption for large files.** Files ≥ 50 MB use an additive,
  magic-byte-detected chunked format (1 MiB chunks, constant memory) that detects
  reordering/truncation as well as tampering. Legacy ciphertext stays
  byte-compatible; decryption auto-detects the format.
- **Database source connectors.** `cloakpii db-export --url ... --output ./dump`
  exports tables to CSV for the pipeline. SQLite needs no extra dependency;
  PostgreSQL and MySQL are optional extras (`cloakpii[postgres]`, `cloakpii[mysql]`).

## [1.4.3] - 2026-06-19

### Documentation
- **No code changes** — identical to 1.4.2 functionally. This release exists so
  the PyPI project page picks up the rewritten README.
- README: pain-point intro, comparison vs Presidio / DIY / gpg, SEO keywords,
  consistent env-var password usage, corrected examples.
- New documentation site (mkdocs-material): https://hellotravisss.github.io/cloakpii/

## [1.4.2] - 2026-06-19

### Security
- **SQLite: unmasked database left on disk when masking failed.** `desensitize_sqlite`
  copied the source DB to the output path and masked it in place; on any mid-masking
  error the transaction rolled back, leaving a verbatim cleartext copy behind. It also
  crashed on `WITHOUT ROWID` tables (`no such column: rowid`), which triggered exactly
  that path. Masking now runs on a temp copy promoted only on success (no residue on
  failure), and rows are identified by `rowid` or primary key as appropriate.
- **Source symlink scope escape.** A symlink under `--source` pointing outside the tree
  was followed, pulling external files into the migration. Paths resolving outside
  `--source` are now skipped (in-tree symlinks still work).
- **Path traversal in `verify`.** `verify_manifest` joined untrusted manifest keys onto
  the target directory, so an absolute/`..` key could read files outside it (a
  file/hash oracle). Such entries are now rejected as `INVALID PATH`.

### Documentation
- README now discloses detection-coverage limits (bare-digit phones, 15-digit Chinese
  IDs, IPv6, free-text names) and points to the ML backend + spot-checking.

## [1.4.1] - 2026-06-17

### Security
- **Numeric PII was silently leaked.** Desensitization only processed
  string-typed values, so PII stored as a number — phones, national IDs, or
  account numbers held in JSON numbers, Parquet int/float columns, or SQLite
  `INTEGER`/`REAL` columns — passed through completely unmasked while the run
  still reported success. CSV/Excel/TSV/text were unaffected (they read values
  as strings), which made the gap easy to miss. JSON, Parquet, and SQLite now
  mask numeric PII as well; non-PII numbers and booleans are preserved, and
  Parquet columns stay numeric unless they actually contain PII. Anyone who
  processed Parquet/SQLite/JSON with v1.4.0 or earlier should re-run.

## [1.4.0] - 2026-06-16

### Security
- **SQL injection** hardening in the SQLite handlers: table/column names are now
  validated (`isidentifier()`) and double-quoted instead of interpolated raw.
- **XXE**: XML parsing now uses `defusedxml` (new hard dependency) with a
  DOCTYPE-stripping fallback, preventing external-entity and entity-expansion
  attacks.
- **rowid correctness**: SQLite UPDATEs now key off the real `rowid` instead of a
  sequential index, which produced wrong updates on tables with deleted rows.
- **No secrets on disk**: `save_config` no longer serializes `password` / `key_file`
  to the YAML config; written configs are created with `0o600` permissions.
- **Restrictive permissions** (`0o600`) on the audit log and on decrypted output
  files, which previously inherited a world-readable umask.
- **No silent network install**: the optional spaCy backend no longer auto-downloads
  and installs a model at runtime; it falls back to regex and prints install
  instructions instead.
- **Decompression-bomb guard**: `decrypt-all` caps `.enc.gz` expansion (2 GiB) to
  avoid OOM on crafted inputs.
- **ReDoS warning**: custom PII regex patterns with nested quantifiers are flagged
  at registration time.
- Decryption errors no longer echo the underlying exception detail.

### Changed
- The encryption password environment variable is now `CLOAKPII_PASSWORD`
  (`ODM_PASSWORD` still works but is deprecated and warns).
- Passing `--password` on the command line now prints a warning recommending the
  environment variable, `--key-file`, or the interactive prompt.

### Credits
- Security fixes for SQL injection, XXE, and rowid contributed by Davy
  (@thedavidweng) in #1.

## [1.3.0] - 2026-06-13

### Added
- **Reversible tokenization mode** (`migrate --mode tokenize`): replaces PII with
  deterministic, reversible pseudonyms instead of irreversible masks. The **same
  value always maps to the same token** — even across separate runs with the same
  password — so joins, GROUP BY, de-duplication and referential integrity are
  preserved. The masked data stays *usable* for analytics, not just archival.
- **`detokenize` command**: reverses tokenization back to original values across a
  decrypted tree, re-parsing each format (so Parquet/Excel/SQLite round-trip
  correctly, not just text). Requires the same password.
- New `tokenize.py` module — AES-GCM-SIV deterministic AEAD, key derived from the
  password with a fixed salt for cross-run stability.

### Changed
- Per-cell transform logic unified into a single `_transform_cell` helper shared by
  all 8 format desensitizers (mask / tokenize / detokenize), removing duplication.

## [1.2.0] - 2026-06-01

### Added
- **Incremental migration / resume**: SQLite state DB tracks processed files by path + SHA-256 hash (`state.py`)
- **ML-assisted PII detection**: optional `pii_ml.py` for content-based PII recognition
- **`assessment` command**: generate a PIPL Security Assessment template (JSON + Markdown)
- **`scan` command**: detect PII in a directory without migrating
- **`decrypt-all` command**: restore an entire migration output tree in one step (derives the key once per distinct salt)
- **Custom PII pattern registration** framework
- Custom exception hierarchy with graceful CLI exit codes (`exceptions.py`)
- Resume integration tests including state-corruption recovery

### Fixed
- `--resume` now detects content changes: an edited file (different hash) is re-processed instead of being skipped on output existence alone
- Credit-card detection now validates the **Luhn checksum**, so random card-shaped numbers are no longer misclassified
- Phone-number detection requires a separator or `+CC` prefix, eliminating false positives on bare integers (order IDs, counts)

### Changed
- **Encryption key is derived once per migration run** instead of once per file — PBKDF2 (480k iterations) no longer runs N times, dramatically speeding up many-file migrations. Output stays password-decryptable (the run salt is stored in every file header)
- Version is now sourced solely from `cloakpii.__version__` (pyproject reads it dynamically)

## [1.1.0] - 2026-06-01

### Added
- Route A: Deep PIPL (China) + PDPA (Singapore) support
- `generate_compliance_report()` with security assessment + DPO notes
- `--compliance-report` flag for migrate command (generates JSON + MD)
- Enhanced `profiles` command with Route A details (DPO, Security Assessment, SLA, etc.)
- `config/china.yaml` and `config/singapore.yaml`
- Dynamic timestamp in compliance reports

### Changed
- `profiles` output now shows sensitive fields, cross-border paths, etc.
- Timestamp in reports is now UTC ISO format instead of hardcoded

## [1.0.0] - 2026-05-28

### Added
- **8 file formats**: CSV, JSON, Excel, Parquet, XML, TSV, SQLite, plain text
- **11 PII types**: email, phone, SSN, credit card, IP, Chinese ID, passport, bank account, IBAN, MAC address, date of birth
- **5 compliance profiles**: GDPR (EU), PDPA (Singapore), CCPA (California), LGPD (Brazil), PIPL (China)
- **Integrity verification**: SHA-256 manifest generation and verification
- **Audit trail**: JSON Lines audit logging for all migration events
- **YAML configuration**: Config files with CLI override support
- **Compression**: gzip compression for encrypted output
- **Resume**: Skip already-processed files with `--resume`
- **Skip patterns**: Glob patterns to exclude files
- **New CLI commands**: `verify`, `status`, `profiles`, `init`
- **Environment variable**: `ODM_PASSWORD` for non-interactive usage
- **Docker support**: Multi-stage Dockerfile and docker-compose.yml
- **GitHub Actions CI**: Automated testing on Python 3.10/3.11/3.12
- **104 comprehensive tests** covering all features

## [0.10.0] - 2026-05-28

### Added
- **New file formats**: Excel (.xlsx), Parquet (.parquet), XML, TSV, SQLite
- **Batch processing**: `--workers N` for parallel processing via ThreadPoolExecutor
- **Progress bar**: tqdm-based progress display (disable with `--no-progress`)
- **Batch size**: `--batch-size N` to limit files processed per run
- **Compliance profiles**: GDPR, PDPA, CCPA, LGPD, PIPL with validation
- **Integrity verification**: SHA-256 manifest generation and verification
- **Audit trail**: JSON Lines audit logging for all migration events
- **Configuration files**: YAML-based config with CLI override support
- **Compression**: gzip compression for encrypted output (`--compress`)
- **Resume support**: `--resume` to skip already-processed files
- **New PII types**: Chinese ID, passport, bank account, IBAN, MAC address, date of birth
- **New CLI commands**: `verify`, `status`, `profiles`
- **Environment variable**: `ODM_PASSWORD` for non-interactive usage

### Changed
- Package structure reorganized into modular files
- `pyproject.toml` now includes all dependencies
- CLI help text improved with examples

## [0.9.0] - 2026-05-28

### Added
- Initial MVP release
- AES-256-GCM encryption with PBKDF2 key derivation
- PII detection and desensitization for CSV, JSON, and plain text
- PII types: email, phone, SSN, credit card, IP address
- Field-name heuristic masking
- CLI with `init`, `encrypt`, `decrypt`, `migrate` commands
- Dry-run mode for migration preview
- 39 comprehensive tests
