from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from .schemas import Finding

DISCLAIMER = ("Heuristic/static-analysis triage only. Findings may be false positives or false negatives; "
              "this is not a formal audit and must not be the sole basis for deployment.")
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def fingerprint(rule_id: str, filename: str, line: int, snippet: str) -> str:
    # Stable across repeated scans; line is included so location changes appear as changed findings.
    raw = f"{rule_id}|{Path(filename).name}|{line}|{' '.join(snippet.split())}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def make_finding(rule_id, title, severity, confidence, source, offset, description, recommendation, detector, filename):
    line = source.count("\\n", 0, offset) + 1
    lines = source.splitlines() or [source]
    snippet = lines[min(line - 1, len(lines) - 1)].strip()[:300]
    return Finding(
        id=rule_id, rule_id=rule_id, title=title, severity=severity, confidence=confidence,
        line=line, snippet=snippet, description=description, recommendation=recommendation,
        detector=detector, fingerprint=fingerprint(rule_id, filename, line, snippet)
    )


def heuristic_analysis(source: str, filename: str) -> list[Finding]:
    findings = []
    for m in re.finditer(r"\btx\.origin\b", source):
        findings.append(make_finding("BS001", "tx.origin usage", "high", "high", source, m.start(),
            "tx.origin appears in the source. If used for authorization, this can enable phishing-style call chains.",
            "Use msg.sender for caller identity and apply explicit, tested access-control rules.", "heuristic:tx-origin", filename))
    for m in re.finditer(r"\.\s*(?:call|delegatecall|staticcall)\s*(?:\[[^\]]*\])?\s*\(", source):
        findings.append(make_finding("BS003", "Low-level external call", "medium", "medium", source, m.start(),
            "A low-level external call was detected. Its safety depends on context, return-value handling, and call ordering.",
            "Review checks-effects-interactions, handle the success value, and test adversarial call paths.", "heuristic:low-level-call", filename))
    pragma = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if pragma and (pragma.group(1).strip().startswith("^") or ">" in pragma.group(1)):
        findings.append(make_finding("BS004", "Floating Solidity compiler pragma", "low", "high", source, pragma.start(),
            f"Compiler pragma is not pinned to one exact version: {pragma.group(1).strip()}.",
            "Pin the compiler in reproducible release/deployment configuration and test that exact version.", "heuristic:pragma", filename))
    if "SPDX-License-Identifier:" not in source:
        findings.append(make_finding("BS006", "Missing SPDX license identifier", "info", "high", source, 0,
            "No SPDX-License-Identifier comment was found.", "Add an SPDX identifier if appropriate for the repository's licensing policy.", "heuristic:spdx", filename))
    unique = {}
    for f in findings:
        unique[(f.rule_id, f.line, f.snippet)] = f
    return sorted(unique.values(), key=lambda f: (ORDER.get(f.severity, 9), f.line, f.rule_id))


def run_slither(source: str, filename: str) -> tuple[list[Finding], str]:
    executable = shutil.which("slither")
    if not executable:
        return [], "unavailable: install Slither to enable"
    suffix = Path(filename).suffix if Path(filename).suffix == ".sol" else ".sol"
    try:
        with tempfile.TemporaryDirectory(prefix="blocksentinel-") as tmp:
            path = Path(tmp) / ("Target" + suffix)
            path.write_text(source, encoding="utf-8")
            proc = subprocess.run(
                [executable, str(path), "--json", "-"],
                capture_output=True, text=True, timeout=90, check=False,
                env={**os.environ, "NO_COLOR": "1"},
            )
            # Slither often returns non-zero if detectors find issues; parse stdout first.
            raw = proc.stdout.strip()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return [], f"error: Slither output was not valid JSON (exit {proc.returncode})"
            results = data.get("results", {}).get("detectors", [])
            findings = []
            for item in results:
                impact = (item.get("impact") or "Informational").lower()
                severity = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "optimization": "info"}.get(impact, "medium")
                elements = item.get("elements") or []
                first = elements[0] if elements else {}
                source_mapping = first.get("source_mapping") or {}
                line_numbers = source_mapping.get("lines") or [1]
                line = int(line_numbers[0]) if line_numbers else 1
                description = str(item.get("description") or item.get("check") or "Slither detector finding")
                snippet = str(first.get("name") or first.get("type") or "")[:300]
                rid = "SLITHER-" + str(item.get("check") or "finding").upper().replace(" ", "-")[:70]
                fp = fingerprint(rid, filename, line, snippet or description[:100])
                findings.append(Finding(
                    id=rid, rule_id=rid, title=str(item.get("check") or "Slither finding").replace("-", " ").title(),
                    severity=severity, confidence="tool-reported", line=line, snippet=snippet,
                    description=description[:4000], recommendation="Review the Slither detector documentation and validate exploitability in context.",
                    detector="slither", fingerprint=fp
                ))
            return findings, f"available: Slither exit {proc.returncode}; {len(findings)} finding(s)"
    except subprocess.TimeoutExpired:
        return [], "error: Slither timed out after 90 seconds"
    except Exception as exc:
        return [], f"error: Slither invocation failed ({type(exc).__name__})"


def run_solc_ast(source: str) -> tuple[dict | None, str]:
    executable = shutil.which("solc")
    if not executable:
        return None, "unavailable: install solc to enable AST parsing"
    payload = {
        "language": "Solidity",
        "sources": {"Target.sol": {"content": source}},
        "settings": {"outputSelection": {"*": {"": ["ast"]}}}
    }
    try:
        proc = subprocess.run([executable, "--standard-json"], input=json.dumps(payload),
            capture_output=True, text=True, timeout=60, check=False)
        output = proc.stdout
        # Some solc builds may emit a non-JSON prefix; locate the first opening brace.
        start = output.find("{")
        if start < 0:
            return None, "error: solc returned no JSON output"
        data = json.loads(output[start:])
        errors = [e for e in data.get("errors", []) if e.get("severity") == "error"]
        if errors:
            return None, "error: Solidity compiler rejected source: " + str(errors[0].get("message", "compile error"))[:240]
        ast = data.get("sources", {}).get("Target.sol", {}).get("ast")
        if not ast:
            return None, "error: compiler response contained no AST"
        return ast, "available: solc AST parsed"
    except subprocess.TimeoutExpired:
        return None, "error: solc timed out"
    except Exception as exc:
        return None, f"error: AST parsing failed ({type(exc).__name__})"


def ast_summary(ast: dict | None) -> dict:
    if not ast:
        return {"contracts": 0, "functions": 0, "nodes": 0}
    counts = Counter()
    stack = [ast]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            node_type = node.get("nodeType")
            if node_type:
                counts[node_type] += 1
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(node)
    return {"contracts": counts["ContractDefinition"], "functions": counts["FunctionDefinition"], "nodes": sum(counts.values())}


def analyze(source: str, filename: str, use_slither: bool = True, use_ast: bool = True):
    findings = heuristic_analysis(source, filename)
    tools = {"heuristics": f"available: {len(findings)} finding(s)"}
    if use_slither:
        slither_findings, slither_status = run_slither(source, filename)
        findings.extend(slither_findings)
        tools["slither"] = slither_status
    else:
        tools["slither"] = "disabled by request"
    ast = None
    if use_ast:
        ast, ast_status = run_solc_ast(source)
        tools["ast"] = ast_status
        tools["ast_summary"] = str(ast_summary(ast))
    else:
        tools["ast"] = "disabled by request"
    dedup = {}
    for f in findings:
        dedup[(f.rule_id, f.fingerprint)] = f
    result = sorted(dedup.values(), key=lambda f: (ORDER.get(f.severity, 9), f.line, f.rule_id))
    return result, tools, ast_summary(ast)
