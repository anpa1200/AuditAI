"""Validate AI responses before treating them as completed assessments."""

from assessment.config import SEVERITY_ORDER


def _text(value, name):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")


def _strings(value, name):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")


def _score(value, name):
    if type(value) is not int or not 0 <= value <= 100:
        raise ValueError(f"{name} must be an integer from 0 to 100")


def validate_module(response):
    if not isinstance(response, dict):
        raise ValueError("Module analysis must be a JSON object")
    _score(response.get("module_risk_score"), "module_risk_score")
    _text(response.get("module_summary"), "module_summary")
    findings = response.get("findings")
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    ids = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be an object")
        for key in ("id", "title", "description", "evidence", "remediation"):
            _text(finding.get(key), f"finding.{key}")
        if not finding["id"] or finding["id"] in ids:
            raise ValueError("Finding IDs must be nonempty and unique within a module")
        ids.add(finding["id"])
        if not isinstance(finding.get("severity"), str) or finding["severity"] not in SEVERITY_ORDER:
            raise ValueError("Invalid finding severity")
        _strings(finding.get("references", []), "finding.references")


def validate_synthesis(response):
    if not isinstance(response, dict):
        raise ValueError("Synthesis must be a JSON object")
    _score(response.get("overall_risk_score"), "overall_risk_score")
    if response.get("overall_risk_rating") not in (*SEVERITY_ORDER, "UNKNOWN"):
        raise ValueError("Invalid overall risk rating")
    _text(response.get("executive_summary"), "executive_summary")
    for key in ("top_10_priorities", "recommended_immediate_actions"):
        _strings(response.get(key), key)
    if not isinstance(response.get("attack_chains"), list):
        raise ValueError("attack_chains must be a list")
    for chain in response["attack_chains"]:
        if not isinstance(chain, dict):
            raise ValueError("Each attack chain must be an object")
        _text(chain.get("title"), "chain.title")
        for key in ("steps", "findings_involved"):
            _strings(chain.get(key), f"chain.{key}")
        for key in ("likelihood", "impact"):
            if chain.get(key) not in ("HIGH", "MEDIUM", "LOW"):
                raise ValueError(f"Invalid chain {key}")
