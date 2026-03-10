import os
import subprocess
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import (
    ETC_PATH, PROC_PATH, SYS_PATH, BOOT_PATH, SYSCTL_CHECKS
)

logger = logging.getLogger(__name__)


class OSHardeningScanner(BaseScanner):
    name = "os_hardening"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["sysctl_params"] = _check_sysctl()
        result["kernel_cmdline"] = _read_cmdline()
        result["apparmor"] = _check_apparmor()
        result["selinux"] = _check_selinux()
        result["secure_boot"] = _check_secure_boot()
        result["grub_config"] = _read_grub_config()
        result["login_defs"] = _read_login_defs()
        result["pam_config"] = _read_pam_config()
        result["issue_files"] = _check_issue_files()
        result["motd"] = _read_motd()
        result["umask"] = _check_umask()
        result["audit_rules"] = _get_audit_rules()
        result["coredump_config"] = _check_coredump()
        result["time_sync"] = _check_time_sync()
        return result, []


def _check_sysctl() -> dict:
    results = {}
    for param, (expected, description) in SYSCTL_CHECKS.items():
        sysfs_path = f"{PROC_PATH}/sys/" + param.replace(".", "/")
        try:
            with open(sysfs_path) as f:
                current = f.read().strip()
            results[param] = {
                "current": current,
                "expected": str(expected),
                "compliant": current == str(expected),
                "description": description,
            }
        except Exception:
            # Try via sysctl command
            try:
                out = subprocess.check_output(
                    ["sysctl", param], text=True, timeout=5, stderr=subprocess.DEVNULL
                )
                current = out.split("=", 1)[1].strip()
                results[param] = {
                    "current": current,
                    "expected": str(expected),
                    "compliant": current == str(expected),
                    "description": description,
                }
            except Exception:
                results[param] = {"error": "not readable", "expected": str(expected)}
    return results


def _read_cmdline() -> str:
    try:
        with open(f"{PROC_PATH}/cmdline") as f:
            return f.read().replace("\x00", " ").strip()
    except Exception:
        return ""


def _check_apparmor() -> dict:
    result = {}
    aa_status = f"{SYS_PATH}/kernel/security/apparmor/profiles"
    if os.path.exists(aa_status):
        try:
            with open(aa_status) as f:
                profiles = f.read().strip().splitlines()
            result["status"] = "enabled"
            result["profile_count"] = len(profiles)
            result["profiles"] = profiles[:50]  # cap for token limit
        except Exception as e:
            result["status"] = "enabled (unreadable)"
            result["error"] = str(e)
    else:
        result["status"] = "not found"

    # Check enforcement mode
    enforce_path = f"{SYS_PATH}/kernel/security/apparmor/enforce"
    if os.path.exists(enforce_path):
        try:
            with open(enforce_path) as f:
                result["enforce"] = f.read().strip()
        except Exception:
            pass

    try:
        result["aa-status"] = subprocess.check_output(
            ["aa-status", "--pretty-json"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

    return result


def _check_selinux() -> dict:
    selinux_path = f"{SYS_PATH}/fs/selinux"
    if not os.path.exists(selinux_path):
        return {"status": "not present"}
    result = {"status": "present"}
    enforce_path = os.path.join(selinux_path, "enforce")
    try:
        with open(enforce_path) as f:
            val = f.read().strip()
        result["enforcing"] = val == "1"
        result["mode"] = "enforcing" if val == "1" else "permissive"
    except Exception:
        pass
    return result


def _check_secure_boot() -> dict:
    efi_path = "/sys/firmware/efi/efivars"
    if not os.path.exists(efi_path):
        return {"status": "EFI not present (legacy boot or no EFI vars)"}
    try:
        sb_vars = [v for v in os.listdir(efi_path) if v.startswith("SecureBoot")]
        return {"status": "EFI present", "secure_boot_vars": sb_vars}
    except Exception as e:
        return {"status": "EFI present", "error": str(e)}


def _read_grub_config() -> dict:
    paths = [
        f"{BOOT_PATH}/grub/grub.cfg",
        f"{BOOT_PATH}/grub2/grub.cfg",
        f"{ETC_PATH}/default/grub",
    ]
    result = {}
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    content = f.read()
                # Only return relevant security lines, not the full file
                security_lines = [
                    line for line in content.splitlines()
                    if any(kw in line.lower() for kw in [
                        "password", "selinux", "apparmor", "audit",
                        "nokaslr", "kaslr", "quiet", "splash", "security",
                        "grub_cmdline_linux", "ro ", "rw "
                    ])
                ]
                result[path] = security_lines
            except Exception:
                result[path] = "unreadable"
    return result


def _read_login_defs() -> dict:
    path = f"{ETC_PATH}/login.defs"
    result = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        result[parts[0]] = parts[1]
    except Exception:
        pass
    return result


def _read_pam_config() -> dict:
    result = {}
    pam_files = [
        "common-auth", "common-password", "common-account",
        "common-session", "su", "sudo", "login", "sshd",
    ]
    for fname in pam_files:
        path = f"{ETC_PATH}/pam.d/{fname}"
        if os.path.exists(path):
            try:
                with open(path) as f:
                    result[fname] = f.read()
            except Exception:
                pass
    return result


def _check_issue_files() -> dict:
    result = {}
    for fname in ["issue", "issue.net"]:
        path = f"{ETC_PATH}/{fname}"
        if os.path.exists(path):
            try:
                with open(path) as f:
                    result[fname] = f.read()
            except Exception:
                pass
    return result


def _read_motd() -> str:
    path = f"{ETC_PATH}/motd"
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def _check_umask() -> dict:
    result = {}
    # Check profile files for umask settings
    for fname in ["/etc/profile", "/etc/bash.bashrc", "/etc/login.defs"]:
        real_path = fname if fname.startswith("/etc/") else f"{ETC_PATH}/{fname}"
        # Use the host etc path
        real_path = ETC_PATH + fname[4:]  # strip /etc
        try:
            with open(real_path) as f:
                for line in f:
                    if "umask" in line.lower() and not line.strip().startswith("#"):
                        result[fname] = line.strip()
        except Exception:
            pass
    return result


def _get_audit_rules() -> str:
    try:
        return subprocess.check_output(
            ["auditctl", "-l"], text=True, timeout=10, stderr=subprocess.DEVNULL
        )
    except Exception:
        # Try reading rules file
        for path in [f"{ETC_PATH}/audit/audit.rules", f"{ETC_PATH}/audit/rules.d"]:
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        return f.read()
                except Exception:
                    pass
        return ""


def _check_coredump() -> dict:
    result = {}
    coredump_conf = f"{ETC_PATH}/systemd/coredump.conf"
    limits_conf = f"{ETC_PATH}/security/limits.conf"
    for path in [coredump_conf, limits_conf]:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    result[path] = f.read()
            except Exception:
                pass
    return result


def _check_time_sync() -> dict:
    result = {}
    try:
        result["timedatectl"] = subprocess.check_output(
            ["timedatectl", "status"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass
    for fname in ["timesyncd.conf", "chrony.conf", "ntp.conf"]:
        path = f"{ETC_PATH}/{fname}"
        if os.path.exists(path):
            try:
                with open(path) as f:
                    result[fname] = f.read()
            except Exception:
                pass
    return result
