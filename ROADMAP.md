# Offshore Data Migrator Roadmap

## v1.1.0 (Current - Route A Focus) ✅
- Deep PIPL (China) and PDPA (Singapore) support
- `generate_compliance_report()` with security assessment + DPO notes
- Sample compliance reports in `examples/`
- Enhanced README with Route A quickstart
- Version bump + initial delegation model

## v1.2.0 (Planned)
- Full PIPL Security Assessment declaration template generator (Markdown + JSON)
- PDPA consent audit matrix
- Dedicated `tests/test_pIPL_pdpa.py` (20+ tests)
- `--compliance-report` flag in CLI migrate command
- China.yaml and singapore.yaml example configs

## v2.0 (Future)
- Multi-jurisdiction orchestration (run multiple profiles in one migration)
- Automated regulatory filing material generation
- Web UI dashboard for compliance teams
- Integration with cloud storage (S3, GCS) with encryption at rest

## Long-term Vision
Become the go-to lightweight tool for companies doing **China-Singapore cross-border data transfers** that require strong encryption + regulatory documentation.
## v1.1.0 Status Update (2026-06-01)
✅ Route A completed:
- Enhanced profiles command with PIPL/PDPA specifics
- --compliance-report working for pipl + pdpa
- china.yaml + singapore.yaml configs created
- Sample reports generated successfully
- All tests green (134 passed)
