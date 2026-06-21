# Security

CloakPII is a security tool, so it's built and audited like one.

## Encryption

- **AES-256-GCM** authenticated encryption.
- Random 12-byte **nonce per file**; random 16-byte **salt per run**, stored in
  the wire header so each blob is self-decryptable by password.
- **PBKDF2-HMAC-SHA256**, 480,000 iterations.

Wire format: `[16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]`.

**Large files** (≥ 50 MB) use an additive **chunked streaming format** (1 MiB
chunks, constant memory) identified by an 8-byte magic header. Each chunk has a
unique nonce and binds its order + finality as GCM associated data, so
reordering and truncation are detected, not just tampering. Legacy ciphertext
stays byte-compatible — decryption auto-detects which format it is reading.

!!! note
    The PBKDF2 iteration count is not stored in the wire format, so it can't be
    changed without breaking existing ciphertext.

## Tokenization

Reversible tokens use **AES-GCM-SIV** (nonce-misuse-resistant) with a
key-derived deterministic nonce, giving stable, join-preserving pseudonyms.
Deterministic tokenization leaks value equality/frequency by design.

## Handling of secrets and output

- Passwords are **never written to disk** (config serialization strips them).
- Audit logs and decrypted output are created with `0o600` permissions.
- `--password` on the CLI prints a warning (visible in `ps` / shell history).

## Parsing & input safety

- XML is parsed with **`defusedxml`** (XXE-safe) with a DOCTYPE-stripping fallback.
- SQLite handlers validate and quote identifiers (**no SQL injection**) and mask
  on a temp copy promoted only on success — a failure never leaves an unmasked
  database behind.
- `decrypt-all` **caps decompression** to resist zip bombs.
- The source walk **stays within `--source`** — a symlink pointing outside the
  tree won't pull external files into the migration.
- `verify` rejects manifest entries with absolute / `..` paths.

## Integrity

The SHA-256 manifest detects **accidental corruption**, not malicious tampering
(an attacker who alters a file can recompute its hash). Tamper protection for
the encrypted output comes from the **AES-GCM authentication tag** — decryption
fails if the ciphertext is modified.

## Reporting a vulnerability

Please open an issue at
[github.com/Hellotravisss/cloakpii/issues](https://github.com/Hellotravisss/cloakpii/issues).
See [`CHANGELOG.md`](https://github.com/Hellotravisss/cloakpii/blob/main/CHANGELOG.md)
for the security history.
