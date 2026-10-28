from .schemas import AnalyzeResponse


def markdown_report(report: AnalyzeResponse) -> str:
    lines = [f"# BlockSentinel report: {report.filename}", "", "> **Disclaimer:** " + report.disclaimer, "",
             "## Tool availability", ""]
    for name, status in report.tools.items():
        lines.append(f"- **{name}:** {status}")
    lines += ["", "## Summary", "", "| Severity | Count |", "|---|---:|"]
    for severity, count in report.summary.items():
        lines.append(f"| {severity.title()} | {count} |")
    lines += ["", "## Findings", ""]
    if not report.findings:
        lines.append("No findings emitted by enabled checks. This does not establish that the contract is secure.")
    for f in report.findings:
        lines += [f"### {f.id} — {f.title}", "", f"- **Severity:** {f.severity}",
                  f"- **Confidence:** {f.confidence}", f"- **Location:** line {f.line}",
                  f"- **Detector:** `{f.detector}`", f"- **Fingerprint:** `{f.fingerprint}`",
                  f"- **Evidence:** `{f.snippet.replace('`', '\\`')}`", "", f.description, "",
                  f"**Recommendation:** {f.recommendation}", ""]
    return "\n".join(lines) + "\n"


def sarif_report(report: AnalyzeResponse) -> dict:
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = {}
    results = []
    for f in report.findings:
        rid = f.rule_id or f.id
        rules[rid] = {"id": rid, "name": f.title, "shortDescription": {"text": f.title},
                      "fullDescription": {"text": f.description[:1000]},
                      "help": {"text": f.recommendation[:1000]}, "defaultConfiguration": {"level": levels.get(f.severity, "warning")}}
        results.append({
            "ruleId": rid, "level": levels.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.filename},
                "region": {"startLine": max(1, f.line), "snippet": {"text": f.snippet}}}}],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
            "properties": {"severity": f.severity, "confidence": f.confidence, "detector": f.detector}
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "BlockSentinel", "version": "0.2.0",
                "informationUri": "https://github.com/your-org/blocksentinel", "rules": list(rules.values())}},
                "results": results, "columnKind": "utf16CodeUnits"}]}
