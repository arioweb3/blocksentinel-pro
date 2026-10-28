from app.analyzer import heuristic_analysis, ast_summary, fingerprint
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_tx_origin_detector():
    findings = heuristic_analysis("contract A { function f() external view returns(address) { return tx.origin; } }", "A.sol")
    assert any(f.rule_id == "BS001" for f in findings)


def test_floating_pragma_detector():
    findings = heuristic_analysis("pragma solidity ^0.8.20; contract A {}", "A.sol")
    assert any(f.rule_id == "BS004" for f in findings)


def test_missing_spdx_detector():
    findings = heuristic_analysis("pragma solidity 0.8.24; contract A {}", "A.sol")
    assert any(f.rule_id == "BS006" for f in findings)


def test_fingerprint_is_stable():
    assert fingerprint("R1", "src/A.sol", 3, "hello") == fingerprint("R1", "A.sol", 3, " hello ")


def test_ast_summary_empty():
    assert ast_summary(None) == {"contracts": 0, "functions": 0, "nodes": 0}


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_without_optional_tools():
    response = client.post("/api/analyze", json={
        "filename": "Demo.sol",
        "source": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.20; contract Demo { function f() external view returns(address) { return tx.origin; } }",
        "use_slither": False,
        "use_ast": False
    })
    assert response.status_code == 200
    assert any(f["rule_id"] == "BS001" for f in response.json()["findings"])


def test_sarif_endpoint():
    response = client.post("/api/report/sarif", json={
        "filename": "Demo.sol", "source": "pragma solidity ^0.8.20; contract Demo {}",
        "use_slither": False, "use_ast": False
    })
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "BlockSentinel"


def test_compare_endpoint():
    source = {"id":"R1","rule_id":"R1","title":"Finding","severity":"low","confidence":"high","line":1,
              "snippet":"x","description":"d","recommendation":"r","detector":"test","fingerprint":"same"}
    other = dict(source, fingerprint="new")
    response = client.post("/api/compare", json={"baseline":[source], "current":[source, other]})
    assert response.status_code == 200
    assert response.json()["summary"] == {"introduced": 1, "resolved": 0, "unchanged": 1}
