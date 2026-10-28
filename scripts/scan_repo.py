#!/usr/bin/env python3
"""Scan repository Solidity files and write SARIF + JSON reports."""
import argparse
import json
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.analyzer import analyze, DISCLAIMER
from app.schemas import AnalyzeResponse
from app.reports import sarif_report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--sarif", default="artifacts/blocksentinel.sarif")
    parser.add_argument("--json", dest="json_path", default="artifacts/blocksentinel.json")
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    all_findings = []
    file_count = 0
    tools_seen = {}
    for path in sorted(root.rglob("*.sol")):
        if any(part in {".git", "node_modules", "lib", "out", "cache", ".venv"} for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        file_count += 1
        relative = path.relative_to(root).as_posix()
        findings, tools, _ = analyze(source, relative, use_slither=True, use_ast=False)
        all_findings.extend(findings)
        tools_seen.update(tools)
    counts = Counter(f.severity for f in all_findings)
    response = AnalyzeResponse(
        filename="repository",
        findings=all_findings,
        summary={s: counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        tools={"files_scanned": str(file_count), **tools_seen},
        disclaimer=DISCLAIMER,
    )
    sarif_path, json_path = Path(args.sarif), Path(args.json_path)
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(json.dumps(sarif_report(response), indent=2), encoding="utf-8")
    json_path.write_text(response.model_dump_json(indent=2), encoding="utf-8")
    print(f"Scanned {file_count} Solidity file(s); findings: {dict(counts)}")
    print(f"SARIF: {sarif_path}; JSON: {json_path}")
    if args.fail_on != "none":
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if any(order.get(f.severity, 4) <= threshold for f in all_findings):
            return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
