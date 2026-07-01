# ML PII Detection Setup

This project supports optional ML-based PII detection using Microsoft Presidio.

## Quick Start

### 1. Create ML Environment

```bash
python -m venv .venv-ml
source .venv-ml/bin/activate
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_sm
deactivate
```

### 2. Run with ML Support

```bash
# Using the helper script (recommended)
./run-with-ml.sh migrate --source examples --compliance-profile pipl --compliance-report

# Or manually
source .venv-ml/bin/activate
cloakpii migrate --source data/
deactivate
```

## How It Works

- Backend precedence: **Presidio** (if installed) → **spaCy** → regex only.
- The spaCy backend needs its model installed **explicitly** — CloakPII does
  **not** auto-download it. Run `python -m spacy download en_core_web_sm`. If the
  model is missing, ML detection is disabled and CloakPII logs a warning and
  falls back to regex + custom patterns (it never fetches a model at runtime).
- Without any ML backend, detection is regex + column-name keywords only.

## Benefits

- Higher accuracy for names, organizations, locations
- Better support for contextual PII detection
- No dependency conflicts with main project
