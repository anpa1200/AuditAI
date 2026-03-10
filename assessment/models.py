from dataclasses import dataclass, field
from typing import Literal, Optional


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    module_name: str
    findings: list[Finding]
    raw_output: dict
    module_risk_score: int
    module_summary: str
    duration_seconds: float
    error: Optional[str] = None


@dataclass
class AttackChain:
    title: str
    steps: list[str]
    findings_involved: list[str]
    likelihood: Literal["HIGH", "MEDIUM", "LOW"]
    impact: Literal["HIGH", "MEDIUM", "LOW"]


@dataclass
class Report:
    hostname: str
    scan_timestamp: str
    os_info: dict
    module_results: list[ModuleResult]
    attack_chains: list[AttackChain]
    top_priorities: list[str]
    overall_risk_score: int
    overall_risk_rating: Severity
    executive_summary: str
    lynis_score: Optional[int]
    recommended_actions: list[str]
    all_findings: list[Finding] = field(default_factory=list)

    def __post_init__(self):
        self.all_findings = []
        for mr in self.module_results:
            self.all_findings.extend(mr.findings)

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.all_findings if f.severity == severity]

    def severity_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
