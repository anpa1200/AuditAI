import os
import subprocess
import json
import logging
import requests
from assessment.scanners.base import BaseScanner
from assessment.config import ETC_PATH, VAR_PATH, DANGEROUS_PACKAGES

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"


class PackagesScanner(BaseScanner):
    name = "packages"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["os_info"] = _read_os_release()
        result["package_manager"] = _detect_package_manager()
        result["installed_packages"] = _get_installed_packages()
        result["dangerous_packages"] = _check_dangerous_packages(
            result["installed_packages"]
        )
        result["cve_findings"] = _check_cves(result["installed_packages"])
        result["package_integrity"] = _check_package_integrity()
        result["auto_updates"] = _check_auto_updates()
        result["os_eol"] = _check_os_eol(result["os_info"])
        result["upgrade_available"] = _check_upgrades()
        return result, []


def _read_os_release() -> dict:
    result = {}
    path = f"{ETC_PATH}/os-release"
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    result[k] = v.strip('"')
    except Exception:
        pass
    return result


def _detect_package_manager() -> str:
    if os.path.exists(f"{VAR_PATH}/lib/dpkg/status"):
        return "dpkg"
    if os.path.exists(f"{VAR_PATH}/lib/rpm"):
        return "rpm"
    return "unknown"


def _get_installed_packages() -> list[dict]:
    # Try dpkg first
    dpkg_status = f"{VAR_PATH}/lib/dpkg/status"
    if os.path.exists(dpkg_status):
        return _parse_dpkg_status(dpkg_status)
    # Try rpm
    try:
        out = subprocess.check_output(
            ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"],
            text=True, timeout=30
        )
        packages = []
        for line in out.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                packages.append({"name": parts[0], "version": parts[1]})
        return packages
    except Exception:
        pass
    return []


def _parse_dpkg_status(path: str) -> list[dict]:
    packages = []
    current = {}
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("Package:"):
                    if current.get("name") and current.get("status", "").startswith("install ok"):
                        packages.append(current)
                    current = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("Version:"):
                    current["version"] = line.split(":", 1)[1].strip()
                elif line.startswith("Status:"):
                    current["status"] = line.split(":", 1)[1].strip()
                elif line.startswith("Architecture:"):
                    current["arch"] = line.split(":", 1)[1].strip()
        if current.get("name") and current.get("status", "").startswith("install ok"):
            packages.append(current)
    except Exception as e:
        logger.warning(f"Failed to parse dpkg status: {e}")
    return packages


def _check_dangerous_packages(packages: list[dict]) -> list[dict]:
    installed_names = {p["name"].lower() for p in packages}
    found = []
    for dangerous in DANGEROUS_PACKAGES:
        if dangerous.lower() in installed_names:
            found.append({"package": dangerous, "reason": "insecure legacy service"})
    return found


def _check_cves(packages: list[dict]) -> list[dict]:
    """Check packages against OSV.dev for known vulnerabilities."""
    findings = []
    # Only check high-risk packages to avoid rate limiting
    # Focus on packages commonly affected by CVEs
    high_risk_prefixes = [
        "openssl", "openssh", "apache2", "nginx", "curl", "wget",
        "libssl", "linux-image", "libc", "bash", "sudo", "python3",
        "perl", "php", "mysql", "postgresql", "redis", "mongodb",
        "docker", "containerd", "runc", "libpam",
    ]

    packages_to_check = [
        p for p in packages
        if any(p["name"].lower().startswith(prefix) for prefix in high_risk_prefixes)
    ][:30]  # Limit API calls

    os_info = _read_os_release()
    ecosystem = "Debian" if os_info.get("ID") in ["debian", "ubuntu"] else "PyPI"

    for pkg in packages_to_check:
        try:
            payload = {
                "package": {
                    "name": pkg["name"],
                    "ecosystem": ecosystem,
                },
                "version": pkg["version"],
            }
            resp = requests.post(OSV_API, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                if vulns:
                    for vuln in vulns[:3]:  # Max 3 CVEs per package
                        findings.append({
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "vuln_id": vuln.get("id", ""),
                            "summary": vuln.get("summary", ""),
                            "severity": vuln.get("database_specific", {}).get("severity", ""),
                            "aliases": vuln.get("aliases", [])[:3],
                        })
        except Exception as e:
            logger.debug(f"OSV check failed for {pkg['name']}: {e}")

    return findings


def _check_package_integrity() -> dict:
    result = {}
    # Check dpkg integrity
    dpkg_admindir = f"{VAR_PATH}/lib/dpkg"
    if os.path.exists(dpkg_admindir):
        try:
            out = subprocess.check_output(
                ["dpkg", "--verify", f"--admindir={dpkg_admindir}"],
                text=True, timeout=60, stderr=subprocess.STDOUT
            )
            lines = out.strip().splitlines()
            result["dpkg_verify"] = {
                "issues_found": len(lines),
                "issues": lines[:20],
            }
        except subprocess.CalledProcessError as e:
            # dpkg --verify exits non-zero when it finds issues
            lines = e.output.strip().splitlines() if e.output else []
            result["dpkg_verify"] = {
                "issues_found": len(lines),
                "issues": lines[:20],
            }
        except Exception as e:
            result["dpkg_verify"] = {"error": str(e)}
    return result


def _check_auto_updates() -> dict:
    result = {}
    # Check unattended-upgrades
    paths = [
        f"{ETC_PATH}/apt/apt.conf.d/20auto-upgrades",
        f"{ETC_PATH}/apt/apt.conf.d/50unattended-upgrades",
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    result[path] = f.read()
            except Exception:
                pass
    return result


def _check_os_eol(os_info: dict) -> dict:
    """Check if the OS version is end-of-life."""
    eol_versions = {
        # Ubuntu EOL dates (simplified)
        "ubuntu": {
            "14.04": "2019-04-30",
            "16.04": "2021-04-30",
            "18.04": "2023-04-30",
            "20.04": "2025-04-30",
            "21.04": "2022-01-20",
            "21.10": "2022-07-14",
            "22.04": "2027-04-30",
            "22.10": "2023-07-20",
            "23.04": "2024-01-25",
            "23.10": "2024-07-11",
            "24.04": "2029-04-30",
        },
        "debian": {
            "8": "2022-06-30",
            "9": "2022-06-30",
            "10": "2024-06-30",
            "11": "2026-08-31",
            "12": "2028-06-30",
        },
    }

    distro_id = os_info.get("ID", "").lower()
    version_id = os_info.get("VERSION_ID", "")

    if distro_id in eol_versions:
        eol_date = eol_versions[distro_id].get(version_id)
        if eol_date:
            return {
                "distro": distro_id,
                "version": version_id,
                "eol_date": eol_date,
                "is_eol": eol_date < "2026-03-09",  # current date
            }

    return {"distro": distro_id, "version": version_id, "eol_known": False}


def _check_upgrades() -> dict:
    try:
        # Check apt for pending security updates
        out = subprocess.check_output(
            ["apt-get", "--simulate", "--quiet", "dist-upgrade"],
            text=True, timeout=30, stderr=subprocess.DEVNULL,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        security_count = sum(
            1 for line in out.splitlines()
            if "security" in line.lower() and line.startswith("Inst")
        )
        total_count = sum(1 for line in out.splitlines() if line.startswith("Inst"))
        return {
            "pending_updates": total_count,
            "security_updates": security_count,
        }
    except Exception:
        return {}
