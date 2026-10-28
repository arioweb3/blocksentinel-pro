# Development guide

## Python

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --reload
```

## Optional tooling

- Slither: install using the official Crytic/Slither instructions.
- solc: install a compiler binary and ensure it is on `PATH`.
- Foundry: install `forge`, then in `contracts/` install `forge-std` and run `forge test -vv`.

## Adding a detector

1. Add a stable rule ID.
2. Emit a `Finding` with evidence, severity, confidence, and remediation.
3. Add positive and negative fixtures in `tests/`.
4. Ensure report output includes the finding.
5. Document known false-positive/false-negative conditions.
