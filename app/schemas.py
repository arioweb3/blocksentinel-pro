from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    source: str = Field(min_length=1, max_length=500_000)
    filename: str = Field(default="Contract.sol", max_length=200)
    use_slither: bool = True
    use_ast: bool = True


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    confidence: str
    line: int
    snippet: str = ""
    description: str
    recommendation: str
    detector: str
    rule_id: str = ""
    fingerprint: str = ""


class AnalyzeResponse(BaseModel):
    filename: str
    findings: list[Finding]
    summary: dict[str, int]
    tools: dict[str, str]
    disclaimer: str


class CompareRequest(BaseModel):
    baseline: list[Finding] = Field(default_factory=list)
    current: list[Finding] = Field(default_factory=list)
