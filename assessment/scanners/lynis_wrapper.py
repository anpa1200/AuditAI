import os
import subprocess
import logging
import tempfile
from assessment.scanners.base import BaseScanner
from assessment.config import HOST_ROOT

logger = logging.getLogger(__name__)

LYNIS_REPORT_PATH = "/tmp/lynis-report.dat"


class LynisScanner(BaseScanner):
    name = "lynis"

    def _scan(self) -> tuple[dict, list]:
        result = {}

        # Run lynis if available
        lynis_path = _find_lynis()
        if not lynis_path:
            raise RuntimeError("lynis not found in PATH")

        # A private per-run directory avoids stale reports and symlink collisions.
        with tempfile.TemporaryDirectory(prefix="auditai-lynis-") as report_dir:
            report_path = os.path.join(report_dir, "report.dat")
            exit_code, output = _run_lynis(lynis_path, report_path)
            if exit_code != 0:
                raise RuntimeError(f"lynis failed (exit {exit_code}): {output[-3000:]}")
            if not os.path.isfile(report_path):
                raise RuntimeError("lynis completed without a report file")
            result.update(_parse_lynis_report(report_path))
            result["exit_code"] = exit_code
            result["output_tail"] = output[-3000:]
            result["status"] = "completed"
        return result, []


def _find_lynis() -> str:
    for path in ["/usr/bin/lynis", "/usr/sbin/lynis", "/usr/local/bin/lynis"]:
        if os.path.exists(path):
            return path
    try:
        out = subprocess.check_output(
            ["which", "lynis"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        return out.strip()
    except Exception:
        return ""


def _run_lynis(lynis_path: str, report_path: str = LYNIS_REPORT_PATH) -> tuple[int, str]:
    cmd = [
        lynis_path, "audit", "system",
        "--no-colors", "--quiet", "--quick",
        f"--report-file={report_path}",
    ]
    if HOST_ROOT and HOST_ROOT != "/":
        cmd.extend(["--rootdir", HOST_ROOT])

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        output = proc.stdout + proc.stderr
        return proc.returncode, output
    except subprocess.TimeoutExpired:
        return -1, "lynis timed out after 10 minutes"
    except Exception as e:
        return -1, str(e)


def _parse_lynis_report(path: str) -> dict:
    report = {
        "hardening_index": None,
        "warnings": [],
        "suggestions": [],
        "test_results": {},
        "details": {},
    }

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()

                if key == "hardening_index":
                    try:
                        report["hardening_index"] = int(value)
                    except ValueError:
                        pass
                elif key == "warning[]":
                    report["warnings"].append(value)
                elif key == "suggestion[]":
                    report["suggestions"].append(value)
                elif key.startswith("test_name["):
                    test_id = key[10:-1]
                    report["test_results"].setdefault(test_id, {})["name"] = value
                elif key.startswith("test_result["):
                    test_id = key[12:-1]
                    if test_id not in report["test_results"]:
                        report["test_results"][test_id] = {}
                    report["test_results"][test_id]["result"] = value
                else:
                    report["details"][key] = value

    except Exception as e:
        raise RuntimeError(f"Failed to parse lynis report: {e}") from e

    # Summarize
    report["warning_count"] = len(report["warnings"])
    report["suggestion_count"] = len(report["suggestions"])

    # Cap lists for token limit
    report["warnings"] = report["warnings"][:50]
    report["suggestions"] = report["suggestions"][:50]

    return report
