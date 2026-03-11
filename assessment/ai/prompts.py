SYSTEM_PROMPT = """You are a senior Linux security engineer performing an authorized vulnerability \
assessment of a production host. You are analyzing raw security scan data collected from the host.

Rules:
- Be specific: cite exact values, file paths, and parameter names from the data provided
- Assign severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- For each finding provide: title, severity, description, evidence (exact data from scan), \
remediation (specific command or config change)
- Do not invent findings not supported by the data
- Distinguish between misconfiguration (fixable) and inherent exposure (architecture decision)
- Output valid JSON exactly matching the provided schema
- Do not add markdown code fences around the JSON"""


MODULE_ANALYSIS_PROMPT = """Analyze the following {module_name} scan results from a Linux host security assessment.

HOST CONTEXT:
OS: {os_name} {os_version}
Kernel: {kernel_version}
Hostname: {hostname}

RAW SCAN DATA:
{scan_output}

Identify security findings. Return at most 12 findings — prioritise by severity, merge duplicates.
Keep each field concise: description ≤ 2 sentences, evidence ≤ 1 line, remediation ≤ 1 command.

Output a JSON object with this exact schema:
{{
  "findings": [
    {{
      "id": "unique_snake_case_id",
      "title": "Short descriptive title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "{module_name}",
      "description": "What the issue is and why it matters (≤2 sentences)",
      "evidence": "Exact values/paths from the scan data (≤1 line)",
      "remediation": "Specific command or config change (≤1 line)",
      "references": []
    }}
  ],
  "module_risk_score": 0,
  "module_summary": "2-3 sentence summary of this module's findings"
}}

The module_risk_score should be 0-100. Output only valid JSON, no other text."""


SYNTHESIS_PROMPT = """You have received security assessment findings from {num_modules} scanner modules \
for a single Linux host. Perform a synthesis analysis.

INDIVIDUAL MODULE FINDINGS:
{all_module_findings_json}

QUANTITATIVE SUMMARY:
- Critical findings: {critical_count}
- High findings: {high_count}
- Medium findings: {medium_count}
- Low findings: {low_count}
- Lynis hardening index: {lynis_score}

Tasks:
1. ATTACK CHAINS: Identify 2-5 realistic attack scenarios where findings combine. Be specific to \
the actual findings present (e.g., "exposed service X running as root Y with SUID binary Z creates \
privilege escalation path").
2. PRIORITY ORDER: Rank the top 10 findings by actual exploitability and impact on THIS host.
3. EXECUTIVE SUMMARY: 3-5 paragraphs suitable for a system owner.
4. OVERALL RISK RATING: CRITICAL/HIGH/MEDIUM/LOW with justification.

Output a JSON object with this exact schema:
{{
  "overall_risk_rating": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_risk_score": 0,
  "executive_summary": "...",
  "attack_chains": [
    {{
      "title": "...",
      "steps": ["step1", "step2"],
      "findings_involved": ["finding_id_1"],
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "HIGH|MEDIUM|LOW"
    }}
  ],
  "top_10_priorities": ["finding_id_1"],
  "recommended_immediate_actions": ["action1"]
}}

Output only valid JSON, no other text."""
