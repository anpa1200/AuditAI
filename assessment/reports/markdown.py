import os
from assessment.models import Report, Finding
from assessment.config import SEVERITY_ORDER


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def generate_markdown(report: Report, output_dir: str) -> str:
    lines = []

    # Header
    lines += [
        f"# Host Vulnerability Assessment Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Hostname** | `{report.hostname}` |",
        f"| **Scan Time** | {report.scan_timestamp} |",
        f"| **OS** | {report.os_info.get('PRETTY_NAME', 'Unknown')} |",
        f"| **Overall Risk** | **{report.overall_risk_rating}** ({report.overall_risk_score}/100) |",
    ]
    if report.lynis_score is not None:
        lines.append(f"| **Lynis Score** | {report.lynis_score}/100 |")
    lines.append("")

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
        report.executive_summary,
        "",
    ]

    # Recommended Actions
    if report.recommended_actions:
        lines += ["## Immediate Actions Required", ""]
        for i, action in enumerate(report.recommended_actions, 1):
            lines.append(f"{i}. {action}")
        lines.append("")

    # Attack Chains
    if report.attack_chains:
        lines += ["## Attack Chain Analysis", ""]
        for chain in report.attack_chains:
            lines += [
                f"### {chain.title}",
                f"",
                f"**Likelihood:** {chain.likelihood} | **Impact:** {chain.impact}",
                f"",
                "**Steps:**",
            ]
            for step in chain.steps:
                lines.append(f"1. {step}")
            if chain.findings_involved:
                lines.append(f"\n**Related Findings:** {', '.join(f'`{f}`' for f in chain.findings_involved)}")
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
                lines.append(f"{i}. {emoji} **{f.title}** ({f.severity}) — {f.category}")
        lines.append("")

    # Module Sections
    lines += ["## Detailed Findings by Module", ""]

    for mr in report.module_results:
        if mr.error:
            lines += [
                f"### {mr.module_name.replace('_', ' ').title()}",
                f"",
                f"> ⚠️ Scanner failed: `{mr.error}`",
                "",
            ]
            continue

        lines += [
            f"### {mr.module_name.replace('_', ' ').title()}",
            f"",
            f"**Risk Score:** {mr.module_risk_score}/100 | "
            f"**Findings:** {len(mr.findings)} | "
            f"**Duration:** {mr.duration_seconds:.1f}s",
            f"",
            mr.module_summary,
            "",
        ]

        if mr.findings:
            # Sort by severity
            sorted_findings = sorted(
                mr.findings,
                key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
            )
            for f in sorted_findings:
                emoji = SEVERITY_EMOJI.get(f.severity, "")
                lines += [
                    f"#### {emoji} {f.title}",
                    f"",
                    f"**Severity:** {f.severity}  ",
                    f"**Description:** {f.description}  ",
                    f"**Evidence:** `{f.evidence}`  ",
                    f"**Remediation:** {f.remediation}",
                ]
                if f.references:
                    refs = " | ".join(f.references)
                    lines.append(f"**References:** {refs}")
                lines.append("")

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
                        lines.append(f"- `{w}`")
                    lines.append("")
                if suggestions:
                    lines += [f"### Suggestions ({len(suggestions)})", ""]
                    for s in suggestions[:30]:
                        lines.append(f"- `{s}`")
                    lines.append("")

    content = "\n".join(lines)
    path = os.path.join(output_dir, f"report_{report.scan_timestamp.replace(':', '-')}.md")
    with open(path, "w") as f:
        f.write(content)
    return path
