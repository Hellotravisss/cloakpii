# CloakPII — Project Summary

CloakPII is a Python CLI that masks (or reversibly tokenizes) the PII in your
data files and databases, encrypts the output with AES-256-GCM, and generates
PIPL / PDPA / GDPR cross-border compliance reports — in one command.

To avoid a second source of truth drifting out of date, the canonical,
always-current references are:

- **Overview & usage** — [README.md](README.md)
- **Full docs site** — https://hellotravisss.github.io/cloakpii/
- **Version history & changes** — [CHANGELOG.md](CHANGELOG.md)
- **Install** — `pip install cloakpii`
- **Source** — https://github.com/Hellotravisss/cloakpii

Current version is defined in `src/cloakpii/__init__.py` and published on
[PyPI](https://pypi.org/project/cloakpii/).
