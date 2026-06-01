# Cross-Border Data Transfer Contract Checklist (PDPA & PIPL)

**For Route A v1.1.0**

## Core Contract Elements
- [ ] Identify legal basis: PDPA (equivalent protection) or PIPL (security assessment / certification / SCC)
- [ ] Include data categories, processing purposes, recipient details
- [ ] Specify security measures matching or exceeding origin jurisdiction
- [ ] Define retention, deletion, breach notification obligations (72h for PDPA)

## PIPL Specific Clauses
- [ ] Reference one of three paths: CAC Security Assessment approval, Certification, or Standard Contract (SCC)
- [ ] Require recipient to obtain separate consent for sensitive PI
- [ ] Include audit rights and cooperation with CAC

## PDPA Specific Clauses
- [ ] Ensure recipient provides level of protection comparable to PDPA
- [ ] DPO contact for recipient included
- [ ] 30-day access request handling mirrored in contract

## Execution & Monitoring
- [ ] Sign contracts before any transfer
- [ ] Maintain register of all cross-border transfers and contracts
- [ ] Conduct periodic reviews (annual) of recipient compliance
- [ ] Update if profile cross_border_conditions change

**compliance.py cross_border_conditions for PIPL**: ["通过安全评估 (Security Assessment)", "通过专业机构认证 (Certification)", "签署标准合同 (Standard Contract / SCCs)"]
