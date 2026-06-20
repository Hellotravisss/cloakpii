# File formats & PII types

## Supported file formats

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

!!! info "Numeric PII is masked too"
    PII held as a *number* (a phone or ID in a JSON number, a Parquet `int`
    column, or a SQLite `INTEGER` column) is masked, not just string values.
    Non-PII numbers are left untouched.

## Supported PII types

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

Credit cards are only masked when they pass the Luhn checksum, which avoids
masking random card-shaped numbers.

## Field-name detection (English + Chinese)

Even when a value doesn't match a regex, a column whose **name** signals PII is
masked. Recognized keywords include English (`name`, `email`, `phone`, `ssn`,
`passport`, `bank_account`, …) **and Chinese** (`姓名`, `邮箱`, `手机号`,
`身份证`, `银行卡号`, …).

## Custom patterns

Add your own detection patterns in `migration.yaml`:

```yaml
custom_pii_patterns:
  - "employee_id:EMP\\d{6}"
```

!!! warning
    Custom patterns run against every value. A nested-quantifier pattern (e.g.
    `(a+)+`) can cause catastrophic backtracking (ReDoS); CloakPII warns when it
    detects that shape.

## Detection limits

The regex + keyword detector does **not** catch: bare-digit phone numbers with
no separators (unless the column name signals PII), 15-digit legacy Chinese IDs,
IPv6 addresses, free-text personal names, or PII glued directly to surrounding
letters. Enable the ML backend for names, and spot-check a sample of any new
dataset before trusting it.
