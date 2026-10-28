from pathlib import Path
from collections import Counter
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from .analyzer import analyze, DISCLAIMER
from .reports import markdown_report, sarif_report
from .schemas import AnalyzeRequest, AnalyzeResponse, CompareRequest, Finding

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"
app = FastAPI(title="BlockSentinel Pro API", description="Solidity security triage, Slither adapter, AST, SARIF and baseline comparison.", version="0.2.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "blocksentinel-pro", "version": "0.2.0"}


@app.get("/api/capabilities")
def capabilities():
    import shutil
    return {"slither": bool(shutil.which("slither")), "solc_ast": bool(shutil.which("solc")),
            "sarif": True, "baseline_comparison": True, "foundry": bool(shutil.which("forge"))}


def run_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    if not request.source.strip():
        raise HTTPException(status_code=422, detail="Source code cannot be empty.")
    findings, tools, ast_stats = analyze(request.source, request.filename, request.use_slither, request.use_ast)
    counts = Counter(f.severity for f in findings)
    summary = {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")}
    tools["ast_counts"] = str(ast_stats)
    return AnalyzeResponse(filename=request.filename, findings=findings, summary=summary, tools=tools, disclaimer=DISCLAIMER)


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest):
    return run_analysis(request)


@app.post("/api/report/markdown", response_class=PlainTextResponse)
def report_markdown(request: AnalyzeRequest):
    return markdown_report(run_analysis(request))


@app.post("/api/report/sarif")
def report_sarif(request: AnalyzeRequest):
    return sarif_report(run_analysis(request))


@app.post("/api/report/json", response_model=AnalyzeResponse)
def report_json(request: AnalyzeRequest):
    return run_analysis(request)


def finding_key(f: Finding):
    return f.fingerprint or f"{f.rule_id}|{f.line}|{f.snippet}"


@app.post("/api/compare")
def compare(request: CompareRequest):
    baseline = {finding_key(f): f for f in request.baseline}
    current = {finding_key(f): f for f in request.current}
    introduced = [f.model_dump() for k, f in current.items() if k not in baseline]
    resolved = [f.model_dump() for k, f in baseline.items() if k not in current]
    unchanged = [f.model_dump() for k, f in current.items() if k in baseline]
    return {"introduced": introduced, "resolved": resolved, "unchanged": unchanged,
            "summary": {"introduced": len(introduced), "resolved": len(resolved), "unchanged": len(unchanged)}}
