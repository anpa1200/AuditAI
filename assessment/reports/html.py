import os
import json
from assessment.models import Report
from assessment.config import SEVERITY_ORDER

SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}

RISK_BADGE_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
    "INFO": "#6b7280",
}


def generate_html(report: Report, output_dir: str) -> str:
    counts = report.severity_counts()
    all_findings_sorted = sorted(
        report.all_findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    # Build findings table rows
    findings_rows = ""
    for f in all_findings_sorted:
        color = SEVERITY_COLOR.get(f.severity, "#6b7280")
        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity}</span></td>
          <td><strong>{_esc(f.title)}</strong></td>
          <td>{_esc(f.category)}</td>
          <td>{_esc(f.description[:200])}</td>
          <td><code>{_esc(f.evidence[:150])}</code></td>
          <td>{_esc(f.remediation[:200])}</td>
        </tr>"""

    # Build module sections
    module_sections = ""
    for mr in report.module_results:
        error_html = f'<div class="error-box">Scanner failed: {_esc(mr.error)}</div>' if mr.error else ""
        findings_html = ""
        if mr.findings:
            sorted_findings = sorted(mr.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            for f in sorted_findings:
                color = SEVERITY_COLOR.get(f.severity, "#6b7280")
                findings_html += f"""
                <div class="finding-card" data-severity="{f.severity}">
                  <div class="finding-header">
                    <span class="badge" style="background:{color}">{f.severity}</span>
                    <strong>{_esc(f.title)}</strong>
                  </div>
                  <p>{_esc(f.description)}</p>
                  <div class="finding-meta">
                    <div><strong>Evidence:</strong> <code>{_esc(f.evidence)}</code></div>
                    <div><strong>Remediation:</strong> {_esc(f.remediation)}</div>
                    {"<div><strong>References:</strong> " + ", ".join(_esc(r) for r in f.references) + "</div>" if f.references else ""}
                  </div>
                </div>"""

        module_sections += f"""
        <div class="module-section">
          <div class="module-header" onclick="toggleSection(this)">
            <span class="module-title">{mr.module_name.replace("_", " ").title()}</span>
            <div class="module-meta">
              <span class="risk-score">Risk: {mr.module_risk_score}/100</span>
              <span class="finding-count">{len(mr.findings)} findings</span>
              <span class="duration">{mr.duration_seconds:.1f}s</span>
              <span class="chevron">▼</span>
            </div>
          </div>
          <div class="module-body collapsed">
            {error_html}
            <p class="module-summary">{_esc(mr.module_summary)}</p>
            {findings_html}
          </div>
        </div>"""

    # Attack chains
    chains_html = ""
    for chain in report.attack_chains:
        steps_html = "".join(f"<li>{_esc(s)}</li>" for s in chain.steps)
        likelihood_color = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#16a34a"}.get(chain.likelihood, "#6b7280")
        impact_color = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#16a34a"}.get(chain.impact, "#6b7280")
        chains_html += f"""
        <div class="attack-chain">
          <h4>{_esc(chain.title)}</h4>
          <div class="chain-badges">
            <span class="badge" style="background:{likelihood_color}">Likelihood: {chain.likelihood}</span>
            <span class="badge" style="background:{impact_color}">Impact: {chain.impact}</span>
          </div>
          <ol>{steps_html}</ol>
          <p><strong>Related findings:</strong> {", ".join(f"<code>{_esc(f)}</code>" for f in chain.findings_involved)}</p>
        </div>"""

    # Actions list
    actions_html = "".join(
        f"<li>{_esc(a)}</li>" for a in report.recommended_actions
    )

    # Top priorities
    finding_map = {f.id: f for f in report.all_findings}
    priorities_html = ""
    for i, fid in enumerate(report.top_priorities[:10], 1):
        f = finding_map.get(fid)
        if f:
            color = SEVERITY_COLOR.get(f.severity, "#6b7280")
            priorities_html += f"""
            <div class="priority-item">
              <span class="priority-num">{i}</span>
              <span class="badge" style="background:{color}">{f.severity}</span>
              <strong>{_esc(f.title)}</strong>
              <span class="category-tag">{_esc(f.category)}</span>
            </div>"""

    risk_color = RISK_BADGE_COLOR.get(report.overall_risk_rating, "#6b7280")
    lynis_html = f"<div class='stat-item'><div class='stat-value'>{report.lynis_score}</div><div class='stat-label'>Lynis Score</div></div>" if report.lynis_score is not None else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment - {_esc(report.hostname)}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
header {{ background: #1e293b; border-radius: 12px; padding: 30px; margin-bottom: 24px; border: 1px solid #334155; }}
header h1 {{ font-size: 1.8rem; color: #f1f5f9; margin-bottom: 8px; }}
.header-meta {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 16px; font-size: 0.9rem; color: #94a3b8; }}
.risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-weight: 700; font-size: 1.1rem; color: white; background: {risk_color}; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.stat-card {{ background: #1e293b; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #334155; }}
.stat-value {{ font-size: 2.5rem; font-weight: 700; }}
.stat-label {{ color: #94a3b8; font-size: 0.85rem; margin-top: 4px; }}
.stat-critical .stat-value {{ color: #dc2626; }}
.stat-high .stat-value {{ color: #ea580c; }}
.stat-medium .stat-value {{ color: #d97706; }}
.stat-low .stat-value {{ color: #2563eb; }}
.stat-info .stat-value {{ color: #6b7280; }}
.stat-item {{ background: #1e293b; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #334155; }}
section {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #334155; }}
h2 {{ font-size: 1.3rem; color: #f1f5f9; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #334155; }}
h3 {{ font-size: 1.1rem; color: #cbd5e1; margin: 16px 0 8px; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: white; }}
.attack-chain {{ background: #0f172a; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 3px solid #ea580c; }}
.attack-chain h4 {{ color: #f97316; margin-bottom: 8px; }}
.chain-badges {{ margin-bottom: 10px; display: flex; gap: 8px; }}
.attack-chain ol {{ padding-left: 20px; color: #cbd5e1; }}
.attack-chain ol li {{ margin-bottom: 4px; }}
.priority-item {{ display: flex; align-items: center; gap: 10px; padding: 10px; background: #0f172a; border-radius: 8px; margin-bottom: 8px; }}
.priority-num {{ width: 28px; height: 28px; background: #334155; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; flex-shrink: 0; }}
.category-tag {{ color: #94a3b8; font-size: 0.8rem; margin-left: auto; }}
.module-section {{ border: 1px solid #334155; border-radius: 10px; margin-bottom: 12px; overflow: hidden; }}
.module-header {{ background: #0f172a; padding: 16px 20px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; user-select: none; }}
.module-header:hover {{ background: #1a2740; }}
.module-title {{ font-weight: 600; color: #f1f5f9; }}
.module-meta {{ display: flex; gap: 16px; font-size: 0.85rem; color: #94a3b8; align-items: center; }}
.risk-score {{ color: #f97316; }}
.finding-count {{ color: #60a5fa; }}
.chevron {{ transition: transform 0.2s; }}
.module-body {{ padding: 16px 20px; }}
.module-body.collapsed {{ display: none; }}
.module-summary {{ color: #94a3b8; margin-bottom: 16px; font-style: italic; }}
.finding-card {{ background: #0f172a; border-radius: 8px; padding: 14px; margin-bottom: 10px; border-left: 3px solid #334155; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
.finding-meta {{ font-size: 0.875rem; color: #94a3b8; margin-top: 8px; }}
.finding-meta div {{ margin-bottom: 4px; }}
.finding-meta code {{ background: #1e293b; padding: 1px 6px; border-radius: 4px; font-size: 0.8rem; color: #a5f3fc; word-break: break-all; }}
.error-box {{ background: #450a0a; border: 1px solid #7f1d1d; border-radius: 6px; padding: 10px 14px; color: #fca5a5; margin-bottom: 12px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
th {{ background: #0f172a; padding: 10px 12px; text-align: left; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
tr:hover td {{ background: #1a2740; }}
code {{ background: #1e293b; padding: 1px 6px; border-radius: 4px; font-size: 0.8rem; color: #a5f3fc; word-break: break-all; }}
.executive-summary {{ color: #cbd5e1; white-space: pre-wrap; }}
ol, ul {{ padding-left: 20px; color: #cbd5e1; }}
ol li, ul li {{ margin-bottom: 6px; }}
.filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
.filter-btn {{ padding: 4px 14px; border-radius: 20px; border: 1px solid #334155; background: #0f172a; color: #94a3b8; cursor: pointer; font-size: 0.8rem; }}
.filter-btn.active, .filter-btn:hover {{ background: #334155; color: #f1f5f9; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🔒 Host Vulnerability Assessment Report</h1>
  <div>
    <span class="risk-badge">{report.overall_risk_rating} RISK — {report.overall_risk_score}/100</span>
  </div>
  <div class="header-meta">
    <span>🖥️ <strong>{_esc(report.hostname)}</strong></span>
    <span>🕒 {report.scan_timestamp}</span>
    <span>🐧 {_esc(report.os_info.get('PRETTY_NAME', 'Unknown OS'))}</span>
    {"<span>🛡️ Lynis: " + str(report.lynis_score) + "/100</span>" if report.lynis_score is not None else ""}
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card stat-critical"><div class="stat-value">{counts.get('CRITICAL', 0)}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card stat-high"><div class="stat-value">{counts.get('HIGH', 0)}</div><div class="stat-label">High</div></div>
  <div class="stat-card stat-medium"><div class="stat-value">{counts.get('MEDIUM', 0)}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card stat-low"><div class="stat-value">{counts.get('LOW', 0)}</div><div class="stat-label">Low</div></div>
  <div class="stat-card stat-info"><div class="stat-value">{counts.get('INFO', 0)}</div><div class="stat-label">Info</div></div>
  {lynis_html}
</div>

<section>
  <h2>Executive Summary</h2>
  <p class="executive-summary">{_esc(report.executive_summary)}</p>
</section>

{"<section><h2>⚡ Immediate Actions Required</h2><ol>" + actions_html + "</ol></section>" if report.recommended_actions else ""}

{"<section><h2>🔗 Attack Chain Analysis</h2>" + chains_html + "</section>" if report.attack_chains else ""}

{"<section><h2>🎯 Top 10 Priorities</h2>" + priorities_html + "</section>" if priorities_html else ""}

<section>
  <h2>All Findings</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('ALL', this)">All ({len(report.all_findings)})</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL', this)" style="color:#dc2626">Critical ({counts.get('CRITICAL',0)})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH', this)" style="color:#ea580c">High ({counts.get('HIGH',0)})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM', this)" style="color:#d97706">Medium ({counts.get('MEDIUM',0)})</button>
    <button class="filter-btn" onclick="filterFindings('LOW', this)" style="color:#2563eb">Low ({counts.get('LOW',0)})</button>
  </div>
  <div style="overflow-x:auto">
  <table id="findings-table">
    <thead><tr>
      <th>Severity</th><th>Title</th><th>Module</th><th>Description</th><th>Evidence</th><th>Remediation</th>
    </tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>
  </div>
</section>

<section>
  <h2>Module Details</h2>
  {module_sections}
</section>

</div>
<script>
function toggleSection(header) {{
  const body = header.nextElementSibling;
  const chevron = header.querySelector('.chevron');
  body.classList.toggle('collapsed');
  chevron.style.transform = body.classList.contains('collapsed') ? '' : 'rotate(180deg)';
}}

function filterFindings(severity, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const rows = document.querySelectorAll('#findings-table tbody tr');
  rows.forEach(row => {{
    if (severity === 'ALL') {{
      row.style.display = '';
    }} else {{
      const sev = row.querySelector('.badge')?.textContent?.trim();
      row.style.display = sev === severity ? '' : 'none';
    }}
  }});
}}
</script>
</body>
</html>"""

    path = os.path.join(output_dir, f"report_{report.scan_timestamp.replace(':', '-')}.html")
    with open(path, "w") as f:
        f.write(html)
    return path


def _esc(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
