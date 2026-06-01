# Compliance Guide for Offshore Data Migration

## Important Legal Notice

This document is for informational purposes only. Always consult qualified legal counsel in both Canada and the destination jurisdiction before migrating data.

## Key Considerations for Canadian Companies

### 1. Data Sovereignty
- Under PIPEDA, organizations must ensure appropriate safeguards when transferring data outside Canada.
- Some regulated industries (finance, healthcare) have additional restrictions.

### 2. Singapore as Destination
Singapore offers:
- Strong data protection under the PDPA
- No general data localization requirement
- Clear framework for cross-border transfers
- Excellent infrastructure and political stability

### 3. Recommended Practices
- Perform data classification before migration
- Apply encryption and desensitization
- Maintain detailed audit logs
- Document the legal basis for transfer
- Implement data retention and deletion policies

## Route A: PIPL + PDPA Specifics (v1.1.0)

### PIPL (China) Profile Highlights (from compliance.py)
- **requires_security_assessment**: True for outbound transfers
- **sensitive_pii_fields**: chinese_id, national_id, credit_card, bank_account, passport, biometric, medical, religious, sexual_orientation (separate consent + enhanced safeguards required)
- **data_localization**: True
- **cross_border_transfer_allowed**: False (default) — must use one of: Security Assessment (CAC), Certification, or Standard Contract (SCCs)
- **Thresholds**: Security assessment typically triggered at 100k+ individuals or 10k+ sensitive PI records
- Use `examples/PIPL_Security_Assessment_Checklist.md` and generated security assessment declaration templates

### PDPA (Singapore) Profile Highlights (from compliance.py)
- **dpo_required**: True — mandatory DPO appointment
- **access_request_days**: 30 — strict timeline for access/correction requests
- **consent_required**: True for collection/use/disclosure
- Cross-border: Recipient must provide comparable protection; maintain contracts
- Use `examples/PDPA_DPO_Appointment_Checklist.md`, `examples/PDPA_30Day_Access_Request_Checklist.md`, and `examples/Cross_Border_Transfer_Contract_Checklist.md`

### Shared Requirements
- encryption_required: True
- audit_log_required: True
- breach_notification_hours: 72 (PDPA)
- All profiles support `get_profile("pipl")` / `get_profile("pdpa")` for validation

## AI Model Weights

Special attention should be given to large AI model files:
- They may contain embedded training data
- Consider model extraction risks
- Apply strong encryption before transfer
- Document model lineage and training data sources

## Audit Trail Requirements

This tool generates logs suitable for:
- Internal compliance reviews
- External audits
- Regulatory inquiries

Keep logs for at least 7 years when dealing with personal data.

## Additional Resources
- See updated RESEARCH_REPORT.md for full PIPL 2021-2025 and PDPA deep dive
- Example templates: examples/ directory (5 new checklists for Route A)
- compliance.py profiles provide machine-readable flags for automation

*Route A focus: PIPL security assessment + PDPA DPO/30-day/cross-border for v1.1.0*
