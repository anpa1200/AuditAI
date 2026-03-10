import os
import subprocess
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import PROC_PATH, SYS_PATH

logger = logging.getLogger(__name__)

# Known EOL kernels (simplified - major version series)
EOL_KERNEL_SERIES = {
    "2.6", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7",
    "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15",
    "3.16", "3.17", "3.18", "3.19", "4.0", "4.1", "4.2", "4.3",
    "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.10", "4.11",
    "4.12", "4.13", "4.14", "4.15", "4.16", "4.17", "4.18", "4.19",
    "4.20", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6",
    "5.7", "5.8", "5.9", "5.10", "5.11", "5.12", "5.13", "5.14",
    "5.15", "5.16", "5.17", "5.18", "5.19",
}


class KernelScanner(BaseScanner):
    name = "kernel"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["version"] = _get_kernel_version()
        result["modules"] = _get_loaded_modules()
        result["cpu_vulnerabilities"] = _check_cpu_vulnerabilities()
        result["lockdown"] = _check_lockdown()
        result["modules_disabled"] = _check_modules_disabled()
        result["dmesg_errors"] = _check_dmesg()
        result["kernel_params"] = _get_kernel_params()
        result["kexec_loaded"] = _check_kexec()
        result["bpf_enabled"] = _check_bpf()
        return result, []


def _get_kernel_version() -> dict:
    result = {}
    try:
        with open(f"{PROC_PATH}/version") as f:
            result["full"] = f.read().strip()
    except Exception:
        pass
    try:
        uname = subprocess.check_output(["uname", "-a"], text=True, timeout=5)
        result["uname"] = uname.strip()
        # Extract version number
        parts = uname.split()
        if len(parts) >= 3:
            version_str = parts[2]
            result["version_string"] = version_str
            # Check major.minor
            ver_parts = version_str.split(".")
            if len(ver_parts) >= 2:
                series = f"{ver_parts[0]}.{ver_parts[1]}"
                result["series"] = series
                result["eol"] = series in EOL_KERNEL_SERIES
    except Exception as e:
        result["error"] = str(e)
    return result


def _get_loaded_modules() -> list[dict]:
    modules = []
    try:
        with open(f"{PROC_PATH}/modules") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    modules.append({
                        "name": parts[0],
                        "size": parts[1],
                        "use_count": parts[2],
                    })
    except Exception as e:
        logger.warning(f"Failed to read modules: {e}")
    return modules


def _check_cpu_vulnerabilities() -> dict:
    vuln_dir = f"{SYS_PATH}/devices/system/cpu/vulnerabilities"
    result = {}
    if not os.path.isdir(vuln_dir):
        return {"status": "directory not found"}
    try:
        for vuln in os.listdir(vuln_dir):
            vuln_path = os.path.join(vuln_dir, vuln)
            try:
                with open(vuln_path) as f:
                    content = f.read().strip()
                mitigation = content.lower()
                result[vuln] = {
                    "status": content,
                    "mitigated": not any(
                        word in mitigation
                        for word in ["vulnerable", "not affected by this cpu"]
                    ) or "mitigation" in mitigation or "not affected" in mitigation,
                }
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


def _check_lockdown() -> dict:
    lockdown_path = f"{SYS_PATH}/kernel/security/lockdown"
    if os.path.exists(lockdown_path):
        try:
            with open(lockdown_path) as f:
                content = f.read().strip()
            return {"enabled": True, "level": content}
        except Exception:
            return {"enabled": True, "error": "unreadable"}
    return {"enabled": False}


def _check_modules_disabled() -> dict:
    path = f"{PROC_PATH}/sys/kernel/modules_disabled"
    try:
        with open(path) as f:
            val = f.read().strip()
        return {"disabled": val == "1", "value": val}
    except Exception:
        return {"error": "not readable"}


def _check_dmesg() -> list[str]:
    try:
        out = subprocess.check_output(
            ["dmesg", "--level=err,warn", "-T"], text=True, timeout=10,
            stderr=subprocess.DEVNULL
        )
        lines = out.strip().splitlines()
        # Filter for security-relevant entries
        security_keywords = [
            "RIP:", "BUG:", "KASAN", "WARNING:", "segfault", "oom", "OOM",
            "Call Trace", "kernel: [", "audit:", "SELinux", "AppArmor",
            "blocked by", "ptrace", "capability", "UBSAN",
        ]
        relevant = [
            line for line in lines
            if any(kw in line for kw in security_keywords)
        ]
        return relevant[:50]
    except Exception:
        return []


def _get_kernel_params() -> dict:
    """Read key kernel security parameters from /proc/sys."""
    params = {
        "kernel.randomize_va_space": f"{PROC_PATH}/sys/kernel/randomize_va_space",
        "kernel.dmesg_restrict": f"{PROC_PATH}/sys/kernel/dmesg_restrict",
        "kernel.kptr_restrict": f"{PROC_PATH}/sys/kernel/kptr_restrict",
        "kernel.perf_event_paranoid": f"{PROC_PATH}/sys/kernel/perf_event_paranoid",
        "kernel.unprivileged_bpf_disabled": f"{PROC_PATH}/sys/kernel/unprivileged_bpf_disabled",
        "kernel.yama.ptrace_scope": f"{PROC_PATH}/sys/kernel/yama/ptrace_scope",
    }
    result = {}
    for name, path in params.items():
        try:
            with open(path) as f:
                result[name] = f.read().strip()
        except Exception:
            result[name] = "not available"
    return result


def _check_kexec() -> dict:
    kexec_path = f"{PROC_PATH}/sys/kernel/kexec_load_disabled"
    try:
        with open(kexec_path) as f:
            val = f.read().strip()
        return {"disabled": val == "1", "value": val}
    except Exception:
        return {"error": "not readable"}


def _check_bpf() -> dict:
    bpf_path = f"{PROC_PATH}/sys/kernel/unprivileged_bpf_disabled"
    try:
        with open(bpf_path) as f:
            val = f.read().strip()
        return {
            "unprivileged_bpf_disabled": val != "0",
            "value": val,
            "note": "0=enabled for all, 1=disabled, 2=disabled+lockdown",
        }
    except Exception:
        return {"error": "not readable"}
