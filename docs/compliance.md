# Compliance (PIPL / PDPA / GDPR)

CloakPII's focus is **cross-border data transfers between China and Singapore**
— PIPL and PDPA — with GDPR, CCPA, and LGPD also supported.

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

## Compliance reports

Add `--compliance-report` to a `pipl` or `pdpa` migration to emit a
`compliance_report_<profile>.json` and `.md` alongside the output:

```bash
cloakpii migrate --source ./data --output ./safe \
  --compliance-profile pipl --compliance-report
```

The report includes:

- a **data-processing summary** computed from the run — files, records, PII
  values masked, data volume, and the personal-data categories handled;
- for **PIPL**, a real **volume-threshold check**: if the run exceeds 100,000
  records, the report flags that a CAC security assessment is required (rather
  than a static note);
- a security-assessment checklist, cross-border transfer legal paths (PIPL),
  and DPO / access-request notes (PDPA).

## PIPL security assessment template

```bash
cloakpii assessment --output security_assessment.json
```

!!! warning "Not legal advice"
    These features generate checklists and declaration templates to help you
    *prepare* a filing. They do not constitute legal advice or a guarantee of
    compliance — have counsel review actual cross-border filings.
