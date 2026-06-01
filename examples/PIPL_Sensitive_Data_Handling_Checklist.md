# PIPL Sensitive Personal Information Handling Checklist

**For Route A v1.1.0**

## Identification
- [ ] Flag all sensitive_pii_fields from compliance.py profile
- [ ] Obtain separate explicit consent for each sensitive category
- [ ] Document necessity and impact assessment for processing sensitive PI

## Protection Measures
- [ ] Apply enhanced encryption (beyond standard)
- [ ] Restrict access to least privilege, with strict audit logging
- [ ] Implement data minimization - collect only required sensitive fields
- [ ] Set strict retention_policy_days where applicable

## Cross-Border Specific
- [ ] Never transfer sensitive PI without one of: CAC security assessment, certification, or standard contract
- [ ] Include purpose limitation and recipient obligations in contracts
- [ ] Notify PI subjects of cross-border risks

**Notes from compliance.py**: sensitive_pii_fields require higher protection; cross_border_transfer_allowed=False by default for PIPL.
