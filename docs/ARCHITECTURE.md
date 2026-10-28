# Architecture

## Pipeline

1. FastAPI validates source input and enforces a 500,000-character request limit.
2. Built-in heuristic checks emit normalized `Finding` records.
3. Optional Slither adapter invokes the installed CLI in a temporary directory and parses its JSON detector output.
4. Optional `solc --standard-json` call requests the compiler AST and summarizes contract/function/node counts.
5. Findings are normalized with a stable fingerprint.
6. Report adapters serialize Markdown, JSON, and SARIF 2.1.0.
7. `/api/compare` classifies fingerprints as introduced, resolved, or unchanged.

## Key files

- `app/analyzer.py`: heuristics, Slither adapter, solc AST integration
- `app/reports.py`: Markdown and SARIF serialization
- `app/main.py`: HTTP API and frontend serving
- `scripts/scan_repo.py`: repository scanner for CI
- `.github/workflows/blocksentinel.yml`: PR workflow
- `contracts/`: Foundry test fixture and tests
- `static/`: cinematic motion UI and workbench

## Important limitation

AST parsing is structural. It is not itself vulnerability detection. Slither and compiler calls run external processes; public multi-tenant hosting needs sandboxing, authentication, quotas, and careful network/filesystem isolation.
