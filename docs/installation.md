# Installation

## From PyPI

```bash
pip install cloakpii
```

Requires Python 3.10+.

## From source

```bash
git clone https://github.com/Hellotravisss/cloakpii.git
cd cloakpii
pip install -e .
```

## Optional: ML-based detection

The built-in detector is regex + column-name keywords. To also catch free-text
personal names and broader entities, install an ML backend (spaCy or Presidio) —
see [`ML_SETUP.md`](https://github.com/Hellotravisss/cloakpii/blob/main/ML_SETUP.md).
CloakPII never downloads a model at runtime; you install it explicitly.

## Verify

```bash
cloakpii --version
cloakpii profiles
```

## Providing the password

Every command needs an encryption password. In order of preference:

```bash
export CLOAKPII_PASSWORD=...        # 1. environment variable (recommended)
cloakpii migrate --key-file pw.txt # 2. read from a file
cloakpii migrate                   # 3. interactive prompt (getpass)
```

!!! danger "Avoid `--password` on the command line"
    A password passed as `--password` is visible in `ps` and your shell
    history. CloakPII prints a warning when you use it.
