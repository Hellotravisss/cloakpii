# Mask vs tokenize

CloakPII has two desensitization modes. Both run through the same encrypt +
compliance pipeline; they differ in whether the result is recoverable.

## Mask (default) — irreversible

```bash
cloakpii migrate --source ./data --output ./safe
```

Each PII value is partially masked (`alice@x.com` → `a***@x******.com`). The
original **cannot** be recovered, even after decrypting. Use this when the data
should never be reversible.

## Tokenize — reversible, join-preserving

```bash
cloakpii migrate --source ./data --output ./safe --mode tokenize
```

Each PII value is replaced by a stable token. **The same input always maps to
the same token** — even across separate runs with the same password:

```text
email,city                              email,city
wei@corp.cn,SH        ──tokenize──▶     tkz_p6dk3s7…,SH    ┐ same value →
wei@corp.cn,BJ                          tkz_p6dk3s7…,BJ    ┘ same token (joins work)
li@corp.cn,SH                           tkz_cx5kz36…,SH
```

So you can still **join, GROUP BY, and de-duplicate** the protected data, and
recover the originals with the password:

```bash
cloakpii decrypt-all  --input ./safe/encrypted --output ./restored
cloakpii detokenize   --input ./restored       --output ./original
```

Tokenization uses **AES-GCM-SIV** (a nonce-misuse-resistant AEAD) with a
key-derived deterministic nonce, which is what gives the equality-preserving
property.

!!! note "Trade-off"
    Deterministic tokenization deliberately leaks value *equality* and
    *frequency* (that's what makes joins work). The token's strength rests on
    the password — use a strong one.

| | Mask | Tokenize |
|---|:---:|:---:|
| Recoverable | ❌ | ✅ (with password) |
| Joins / dedup still work | ❌ | ✅ |
| Leaks value equality | ❌ | ✅ (by design) |
| Use when… | data must never be reversible | downstream needs referential integrity |
