import json
import logging
import time
from assessment.models import ModuleResult, Finding, AttackChain, Report
from assessment.ai.client import AIClient
from assessment.ai.prompts import MODULE_ANALYSIS_PROMPT, SYNTHESIS_PROMPT
from assessment.config import SEVERITY_ORDER

logger = logging.getLogger(__name__)

MAX_SCAN_OUTPUT_CHARS = 40_000  # keep prompts small to avoid truncated JSON
INTER_REQUEST_DELAY = 3  # seconds between API calls (Tier 1 rate limit)


class Analyzer:
    def __init__(self, client: AIClient, host_context: dict):
        self.client = client
        self.host_context = host_context

    def analyze_modules(self, module_results: list[ModuleResult]) -> list[ModuleResult]:
        """Run per-module AI analysis sequentially to respect Tier 1 rate limits."""
        updated = []

        to_analyze = [mr for mr in module_results if not mr.error]
        for i, mr in enumerate(to_analyze):
            try:
                updated.append(self._analyze_module(mr))
            except Exception as e:
                logger.error(f"Module analysis failed for {mr.module_name}: {e}")
                updated.append(mr)
            # Pause between calls except after the last one
            if i < len(to_analyze) - 1:
                time.sleep(INTER_REQUEST_DELAY)

        # Add errored modules as-is
        errored = [mr for mr in module_results if mr.error]
        updated.extend(errored)

        # Preserve original order
        order = {mr.module_name: i for i, mr in enumerate(module_results)}
        updated.sort(key=lambda mr: order.get(mr.module_name, 999))

        return updated

    def _analyze_module(self, mr: ModuleResult) -> ModuleResult:
        logger.info(f"AI analyzing module: {mr.module_name}")

        scan_json = json.dumps(mr.raw_output, indent=2, default=str)
        if len(scan_json) > MAX_SCAN_OUTPUT_CHARS:
            scan_json = scan_json[:MAX_SCAN_OUTPUT_CHARS] + "\n... [truncated]"

        prompt = MODULE_ANALYSIS_PROMPT.format(
            module_name=mr.module_name,
            os_name=self.host_context.get("os_name", "Linux"),
            os_version=self.host_context.get("os_version", ""),
            kernel_version=self.host_context.get("kernel_version", ""),
            hostname=self.host_context.get("hostname", "unknown"),
            scan_output=scan_json,
        )

        response = self.client.analyze(prompt, max_tokens=4096)

        findings = []
        for f in response.get("findings", []):
            try:
                findings.append(Finding(
                    id=f.get("id", f"finding_{len(findings)}"),
                    title=f.get("title", "Untitled"),
                    severity=f.get("severity", "INFO"),
                    category=mr.module_name,
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    references=f.get("references", []),
                ))
            except Exception as e:
                logger.warning(f"Failed to parse finding: {e}")

        mr.findings = findings
        mr.module_risk_score = response.get("module_risk_score", 0)
        mr.module_summary = response.get("module_summary", "")

        logger.info(
            f"Module {mr.module_name}: {len(findings)} findings, "
            f"risk score {mr.module_risk_score}"
        )
        return mr

    def synthesize(self, module_results: list[ModuleResult]) -> dict:
        """Run cross-module synthesis to get attack chains, priorities, summary."""
        logger.info("Running AI synthesis across all modules...")

        all_findings = []
        module_summaries = []
        lynis_score = "N/A"

        for mr in module_results:
            if mr.module_name == "lynis":
                lynis_idx = mr.raw_output.get("hardening_index")
                if lynis_idx is not None:
                    lynis_score = str(lynis_idx)
            findings_data = [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "evidence": f.evidence[:500],
                }
                for f in mr.findings
            ]
            module_summaries.append({
                "module": mr.module_name,
                "risk_score": mr.module_risk_score,
                "summary": mr.module_summary,
                "findings": findings_data,
            })
            all_findings.extend(findings_data)

        # Count by severity
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        findings_json = json.dumps(module_summaries, indent=2, default=str)
        if len(findings_json) > 100_000:
            findings_json = findings_json[:100_000] + "\n... [truncated]"

        prompt = SYNTHESIS_PROMPT.format(
            num_modules=len(module_results),
            all_module_findings_json=findings_json,
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            lynis_score=lynis_score,
        )

        return self.client.analyze(prompt, max_tokens=8192)


def build_report(
    module_results: list[ModuleResult],
    synthesis: dict,
    host_context: dict,
    scan_timestamp: str,
) -> Report:
    attack_chains = []
    for chain in synthesis.get("attack_chains", []):
        attack_chains.append(AttackChain(
            title=chain.get("title", ""),
            steps=chain.get("steps", []),
            findings_involved=chain.get("findings_involved", []),
            likelihood=chain.get("likelihood", "MEDIUM"),
            impact=chain.get("impact", "MEDIUM"),
        ))

    lynis_score = None
    for mr in module_results:
        if mr.module_name == "lynis":
            lynis_score = mr.raw_output.get("hardening_index")

    report = Report(
        hostname=host_context.get("hostname", "unknown"),
        scan_timestamp=scan_timestamp,
        os_info=host_context.get("os_info", {}),
        module_results=module_results,
        attack_chains=attack_chains,
        top_priorities=synthesis.get("top_10_priorities", []),
        overall_risk_score=synthesis.get("overall_risk_score", 0),
        overall_risk_rating=synthesis.get("overall_risk_rating", "MEDIUM"),
        executive_summary=synthesis.get("executive_summary", ""),
        lynis_score=lynis_score,
        recommended_actions=synthesis.get("recommended_immediate_actions", []),
    )
    return report
