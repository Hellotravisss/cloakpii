# Configuration

Create a `migration.yaml` for reusable settings. CLI arguments override it.

```yaml
source: /path/to/data
output: /path/to/output
target: singapore
compliance_profile: pdpa
workers: 4
batch_size: 0
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

## Per-field policies

By default every field is auto-detected and masked (or tokenized in
`--mode tokenize`). For granular control, pin specific fields to an action with
`field_policies` — it overrides both the global mode and the auto-detector for
those fields:

```yaml
field_policies:
  email:    tokenize    # reversible, join-preserving
  phone:    mask        # irreversible
  salary:   drop        # remove the column/key entirely
  user_id:  keep        # leave untouched
```

| Action     | Effect                                                        |
|------------|--------------------------------------------------------------|
| `mask`     | Irreversibly mask the value (forced, even if no regex matches) |
| `tokenize` | Replace with a stable reversible token                       |
| `drop`     | Remove the field — column (CSV/TSV/Excel/Parquet/SQLite), key (JSON), or element/attribute (XML) |
| `keep`     | Leave the value exactly as-is                                |

Field names match case-insensitively. Fields not listed fall back to the
default auto-detect behaviour. An unknown action is ignored with a warning.

!!! danger "Secrets are never written to a config file"
    CloakPII refuses to serialize `password` / `key_file` into a config file.
    Provide the password via `CLOAKPII_PASSWORD`, `--key-file`, or the
    interactive prompt. Config files are created with `0o600` permissions.

## Precedence

The password is resolved in this order:

1. `--password` (warns about `ps` / shell-history exposure)
2. `--key-file`
3. `password` / `key_file` in the config file (discouraged — see above)
4. `CLOAKPII_PASSWORD` environment variable (legacy alias: `ODM_PASSWORD`)
5. Interactive prompt (`getpass`)
