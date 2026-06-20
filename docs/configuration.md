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
