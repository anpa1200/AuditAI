import html
import json
import re

from assessment.config import SEVERITY_ORDER
from assessment.models import Report
from assessment.reports.writer import write_report

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def generate_markdown(report: Report, output_dir: str) -> str:
    score = "unavailable" if report.overall_risk_score is None else f"{report.overall_risk_score}/100"
    lines = []

    # Header
    lines += [
        "# Host Vulnerability Assessment Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Hostname** | {_esc(report.hostname)} |",
        f"| **Scan Time** | {_esc(report.scan_timestamp)} |",
        f"| **OS** | {_esc(report.os_info.get('PRETTY_NAME', 'Unknown'))} |",
        f"| **Overall Risk** | **{_esc(report.overall_risk_rating)}** ({score}) |",
    ]
    if report.lynis_score is not None:
        lines.append(f"| **Lynis Score** | {report.lynis_score}/100 |")
    lines.append("")

    if report.error:
        lines += [f"> ⚠️ Assessment incomplete: {_esc(report.error)}", ""]

    # Severity summary
    counts = report.severity_counts()
    lines += [
        "## Finding Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev} | {counts.get(sev, 0)} |")
    lines.append("")

    # Executive Summary
    lines += [
        "## Executive Summary",
        "",
        _esc(report.executive_summary),
        "",
    ]

    # Recommended Actions
    if report.recommended_actions:
        lines += ["## Immediate Actions Required", ""]
        for i, action in enumerate(report.recommended_actions, 1):
            lines.append(f"{i}. {_esc(action)}")
        lines.append("")

    # Attack Chains
    if report.attack_chains:
        lines += ["## Attack Chain Analysis", ""]
        for chain in report.attack_chains:
            lines += [
                f"### {_esc(chain.title)}",
                "",
                f"**Likelihood:** {_esc(chain.likelihood)} | **Impact:** {_esc(chain.impact)}",
                "",
                "**Steps:**",
            ]
            for step in chain.steps:
                lines.append(f"1. {_esc(step)}")
            if chain.findings_involved:
                lines.append(f"\n**Related Findings:** {', '.join(_esc(f) for f in chain.findings_involved)}")
            lines.append("")

    # Top Priorities
    if report.top_priorities:
        lines += ["## Top Priority Findings", ""]
        # Build finding lookup
        finding_map = {f.id: f for f in report.all_findings}
        for i, fid in enumerate(report.top_priorities[:10], 1):
            f = finding_map.get(fid)
            if f:
                emoji = SEVERITY_EMOJI.get(f.severity, "")
                lines.append(f"{i}. {emoji} **{_esc(f.title)}** ({_esc(f.severity)}) — {_esc(f.category)}")
        lines.append("")

    # Module Sections
    lines += ["## Detailed Findings by Module", ""]

    for mr in report.module_results:
        module_score = "unavailable" if mr.module_risk_score is None else f"{mr.module_risk_score}/100"
        lines += [
            f"### {_esc(mr.module_name.replace('_', ' ').title())}",
            "",
            (f"**Risk Score:** {module_score} | "
            f"**Findings:** {len(mr.findings)} | "
            f"**Duration:** {mr.duration_seconds:.1f}s"),
            "",
            _esc(mr.module_summary),
            "",
        ]

        if mr.error:
            lines += [f"> ⚠️ Module failed: {_esc(mr.error)}", ""]

        if mr.findings:
            # Sort by severity
            sorted_findings = sorted(
                mr.findings,
                key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
            )
            for f in sorted_findings:
                emoji = SEVERITY_EMOJI.get(f.severity, "")
                lines += [
                    f"#### {emoji} {_esc(f.title)}",
                    "",
                    f"**Severity:** {_esc(f.severity)}  ",
                    f"**Description:** {_esc(f.description)}  ",
                    f"**Evidence:** {_esc(f.evidence)}  ",
                    f"**Remediation:** {_esc(f.remediation)}",
                ]
                if f.references:
                    refs = " | ".join(_esc(ref) for ref in f.references)
                    lines.append(f"**References:** {refs}")
                lines.append("")

        if mr.raw_output:
            raw_json = json.dumps(mr.raw_output, indent=2, ensure_ascii=False, default=str)
            # A longer fence prevents scanner output from ending the code block.
            runs = re.findall(r"`+", raw_json)
            fence = "`" * max(3, max((len(run) + 1 for run in runs), default=3))
            lines += ["#### Raw Scanner Output", "", f"{fence}json", raw_json, fence, ""]

    # Lynis details
    for mr in report.module_results:
        if mr.module_name == "lynis" and not mr.error:
            raw = mr.raw_output
            warnings = raw.get("warnings", [])
            suggestions = raw.get("suggestions", [])
            if warnings or suggestions:
                lines += ["## Lynis Details", ""]
                if warnings:
                    lines += [f"### Warnings ({len(warnings)})", ""]
                    for w in warnings:
                        lines.append(f"- {_esc(w)}")
                    lines.append("")
                if suggestions:
                    lines += [f"### Suggestions ({len(suggestions)})", ""]
                    for s in suggestions[:30]:
                        lines.append(f"- {_esc(s)}")
                    lines.append("")

    content = "\n".join(lines)
    return write_report(output_dir, report.scan_timestamp, "md", content)


def _esc(text: str) -> str:
    """Render scanner and model content as text, not active Markdown or HTML."""
    text = re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", str(text))
    text = html.escape(text, quote=True)
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")
