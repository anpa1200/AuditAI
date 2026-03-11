"""
Pre-process raw scanner output before sending to the AI.

Goals:
  - Drop bulk low-signal data (full package lists, full process tables)
  - Strip known-safe baseline items already accounted for
  - Compress verbose text blobs to key signals only
  - Keep everything that is actually anomalous or high-risk

Result: prompt size drops 60-80%, AI focuses on real findings.
"""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ─── Public entry point ───────────────────────────────────────────────────────

def preprocess(module_name: str, raw: dict) -> dict:
    """Return a filtered/compressed copy of raw scanner output."""
    handler = _HANDLERS.get(module_name)
    if handler:
        try:
            return handler(raw)
        except Exception as e:
            logger.warning(f"Preprocessor failed for {module_name}: {e}")
    return raw  # fallback: pass through unchanged


# ─── Per-module handlers ──────────────────────────────────────────────────────

def _process_network(raw: dict) -> dict:
    out = {}

    # Interfaces: keep only name, state, addresses
    ifaces = raw.get("interfaces", [])
    out["interfaces"] = [
        {
            "name": i.get("ifname"),
            "state": i.get("operstate"),
            "addresses": [
                {"family": a.get("family"), "addr": a.get("local")}
                for a in i.get("addr_info", [])
            ],
        }
        for i in ifaces
        if isinstance(i, dict)
    ]

    # nmap: parse XML → list of open ports only
    for key in ("nmap_localhost", "nmap_primary"):
        nmap = raw.get(key, {})
        if isinstance(nmap, dict) and "xml" in nmap:
            out[key] = {
                "target": nmap.get("target"),
                "open_ports": _parse_nmap_xml(nmap["xml"]),
                "note": nmap.get("note", ""),
            }
        elif isinstance(nmap, dict):
            out[key] = nmap  # keep error or empty

    # ss output: parse to structured list, drop header
    ss_raw = raw.get("open_ports_ss", "")
    out["open_ports_ss"] = _parse_ss(ss_raw)

    # Firewall: summarise iptables (keep first 60 lines, flag ACCEPT-all)
    ipt = raw.get("firewall_iptables", {})
    out["firewall_iptables"] = _summarise_iptables(ipt)
    out["firewall_ufw"] = _trim(raw.get("firewall_ufw", ""), 80)
    out["firewall_nftables"] = _trim(raw.get("firewall_nftables", ""), 80)

    # Small fields: pass through
    for k in ("hostname", "primary_ip", "routing_table", "dns_config",
               "hosts_file", "ipv6_interfaces"):
        if k in raw:
            out[k] = _trim(raw[k], 30)

    return out


def _process_processes(raw: dict) -> dict:
    out = {}
    out["total_process_count"] = raw.get("total_process_count", 0)

    # Keep suspicious, in-tmp, zombies in full
    out["suspicious_processes"] = raw.get("suspicious_processes", [])
    out["processes_in_tmp"] = raw.get("processes_in_tmp", [])
    out["zombie_processes"] = raw.get("zombie_processes", [])

    # Root processes: dedup by name, keep max 30
    root = raw.get("root_processes", [])
    seen_names: set = set()
    deduped = []
    for p in root:
        name = p.get("name", "")
        if name not in seen_names:
            seen_names.add(name)
            deduped.append({k: p[k] for k in ("pid", "name", "cmdline", "exe", "capabilities")
                            if k in p})
    out["root_processes_unique"] = deduped[:30]
    out["root_process_count"] = len(root)

    # Privileged: keep but drop cmdline bloat
    priv = raw.get("privileged_processes", [])
    out["privileged_processes"] = [
        {k: p[k] for k in ("pid", "name", "exe", "capabilities", "uid") if k in p}
        for p in priv[:40]
    ]

    # Drop process_list (raw 200-entry table — too noisy)
    out["network_connections"] = _trim(raw.get("processes_with_network", ""), 60)

    return out


def _process_packages(raw: dict) -> dict:
    out = {}

    # Drop installed_packages — hundreds of entries, low signal
    total = len(raw.get("installed_packages", []))
    out["total_installed_packages"] = total

    # Keep all CVE and dangerous package findings
    out["cve_findings"] = raw.get("cve_findings", [])
    out["dangerous_packages"] = raw.get("dangerous_packages", [])
    out["package_integrity"] = raw.get("package_integrity", {})
    out["auto_updates"] = raw.get("auto_updates", {})
    out["upgrade_available"] = raw.get("upgrade_available", {})
    out["os_eol"] = raw.get("os_eol", {})
    out["os_info"] = {
        k: raw.get("os_info", {}).get(k)
        for k in ("NAME", "VERSION", "VERSION_ID", "ID", "PRETTY_NAME")
    }

    return out


def _process_filesystem(raw: dict) -> dict:
    out = {}

    # SUID: drop all_suid (huge), keep unknown and counts
    suid = raw.get("suid_sgid_files", {})
    out["suid_sgid_summary"] = {
        "suid_count": suid.get("suid_count", 0),
        "sgid_count": suid.get("sgid_count", 0),
        "unknown_suid_binaries": suid.get("unknown_suid", []),
    }

    # World-writable dirs: only risky ones (no sticky bit), cap 20
    ww_dirs = raw.get("world_writable_dirs", [])
    out["world_writable_dirs_risky"] = [
        d for d in ww_dirs if d.get("risky")
    ][:20]
    out["world_writable_dirs_total"] = len(ww_dirs)

    # World-writable system files: always interesting
    out["world_writable_files"] = raw.get("world_writable_files", [])

    # Sensitive file permissions: keep only misconfigured ones
    sens = raw.get("sensitive_file_perms", {})
    out["sensitive_file_perms_issues"] = {
        path: info for path, info in sens.items()
        if isinstance(info, dict) and info.get("too_permissive")
    }

    # Unowned files
    out["unowned_files"] = raw.get("unowned_files", [])[:20]

    # Small fields pass through
    for k in ("tmp_permissions", "cron_perms", "ssh_host_key_perms",
               "root_history", "writeable_path_dirs"):
        if k in raw:
            out[k] = raw[k]

    return out


def _process_users(raw: dict) -> dict:
    out = {}

    # passwd: keep only login-shell users and root; drop service accounts
    passwd = raw.get("passwd", [])
    out["login_users"] = [
        u for u in passwd
        if u.get("has_login_shell") or u.get("uid") == 0
    ]
    out["total_user_count"] = len(passwd)

    # Keep high-value fields intact
    for k in ("shadow_permissions", "sudo_config", "ssh_config",
               "user_ssh_keys", "legacy_files", "password_policy",
               "su_restrictions", "logged_in_users"):
        if k in raw:
            out[k] = raw[k]

    # Last/failed logins: trim to 20 lines
    out["last_logins"] = _trim(raw.get("last_logins", ""), 20)
    out["failed_logins"] = _trim(raw.get("failed_logins", ""), 20)

    return out


def _process_os_hardening(raw: dict) -> dict:
    out = {}

    # Sysctl: keep only non-compliant parameters
    sysctl = raw.get("sysctl_params", {})
    out["sysctl_non_compliant"] = {
        param: info for param, info in sysctl.items()
        if isinstance(info, dict) and not info.get("compliant", True)
    }
    out["sysctl_compliant_count"] = sum(
        1 for info in sysctl.values()
        if isinstance(info, dict) and info.get("compliant", False)
    )
    out["sysctl_total_checked"] = len(sysctl)

    # PAM config: trim (can be very long)
    out["pam_config"] = _trim(raw.get("pam_config", ""), 60)
    out["grub_config"] = _trim(raw.get("grub_config", ""), 40)

    # Pass through smaller fields
    for k in ("kernel_cmdline", "apparmor", "selinux", "secure_boot",
               "login_defs", "issue_files", "umask", "audit_rules",
               "coredump_config", "time_sync"):
        if k in raw:
            out[k] = raw[k]

    return out


def _process_services(raw: dict) -> dict:
    out = {}

    # Systemd units: keep failed (active=="failed" or sub=="failed") + count enabled
    units = raw.get("systemd_units", [])
    if isinstance(units, list):
        out["failed_units"] = [
            u for u in units
            if u.get("active") == "failed" or u.get("sub") == "failed"
        ]
        out["enabled_unit_count"] = len([u for u in units if u.get("enabled")])
        out["total_unit_count"] = len(units)
    else:
        out["systemd_units"] = _trim(str(units), 60)

    out["systemd_failed"] = raw.get("systemd_failed", [])

    # Docker socket — always keep (critical if world-readable)
    out["docker_socket"] = raw.get("docker_socket", {})

    # Cron: trim large files but keep structure
    cron = raw.get("cron_jobs", {})
    out["cron_jobs"] = {k: _trim(v, 30) for k, v in cron.items()} if isinstance(cron, dict) else cron

    # Pass through smaller fields
    for k in ("inetd_xinetd", "at_jobs", "init_scripts", "timers", "listening_processes"):
        if k in raw:
            out[k] = _trim(raw[k], 30) if isinstance(raw[k], str) else raw[k]

    return out


def _process_kernel(raw: dict) -> dict:
    out = {}

    # CPU vulnerabilities: keep only non-mitigated
    vulns = raw.get("cpu_vulnerabilities", {})
    if isinstance(vulns, dict):
        out["cpu_vulnerabilities_not_mitigated"] = {
            vuln: status for vuln, status in vulns.items()
            if isinstance(status, str) and "mitigation" not in status.lower()
            and "not affected" not in status.lower()
        }
        out["cpu_vulnerabilities_total"] = len(vulns)
    else:
        out["cpu_vulnerabilities"] = vulns

    # Pass through
    for k in ("kernel_version", "kernel_lockdown", "loaded_modules",
               "dmesg_errors", "kernel_config"):
        if k in raw:
            out[k] = raw[k]

    return out


def _process_lynis(raw: dict) -> dict:
    # Lynis output is already fairly structured; just trim large text fields
    out = {}
    for k, v in raw.items():
        if isinstance(v, str) and len(v) > 3000:
            out[k] = v[:3000] + "\n... [truncated by preprocessor]"
        else:
            out[k] = v
    return out


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _trim(value: Any, max_lines: int) -> Any:
    """Trim a string to max_lines lines. Pass non-strings through."""
    if not isinstance(value, str):
        return value
    lines = value.splitlines()
    if len(lines) <= max_lines:
        return value
    return "\n".join(lines[:max_lines]) + f"\n... [{len(lines) - max_lines} lines trimmed]"


def _parse_nmap_xml(xml: str) -> list[dict]:
    """Extract open port info from nmap XML output."""
    ports = []
    try:
        for m in re.finditer(
            r'<port protocol="(\w+)" portid="(\d+)".*?'
            r'<state state="(\w+)".*?'
            r'(?:<service name="([^"]*)"[^/]*/?>)?',
            xml, re.DOTALL
        ):
            if m.group(3) == "open":
                ports.append({
                    "protocol": m.group(1),
                    "port": int(m.group(2)),
                    "state": m.group(3),
                    "service": m.group(4) or "",
                })
    except Exception:
        pass
    return ports


def _parse_ss(ss_output: str) -> list[dict]:
    """Parse `ss -tlnpu` output into structured list."""
    results = []
    if not ss_output:
        return results
    for line in ss_output.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 5:
            results.append({
                "proto": parts[0],
                "state": parts[1],
                "local_addr": parts[4],
                "process": parts[6] if len(parts) > 6 else "",
            })
    return results


def _summarise_iptables(ipt: dict) -> dict:
    """Summarise iptables rules — flag if default ACCEPT policy exists."""
    summary = {}
    for table, rules in ipt.items():
        if not isinstance(rules, str):
            summary[table] = rules
            continue
        lines = rules.splitlines()
        has_accept_all = any(
            re.search(r"policy ACCEPT", line) for line in lines
        )
        rule_count = sum(1 for line in lines if line.strip() and not line.startswith("Chain") and not line.startswith("target"))
        summary[table] = {
            "rule_count": rule_count,
            "default_accept_policy": has_accept_all,
            "rules_preview": "\n".join(lines[:25]),
        }
    return summary


# ─── Handler registry ─────────────────────────────────────────────────────────

_HANDLERS = {
    "network":      _process_network,
    "processes":    _process_processes,
    "packages":     _process_packages,
    "filesystem":   _process_filesystem,
    "users":        _process_users,
    "os_hardening": _process_os_hardening,
    "services":     _process_services,
    "kernel":       _process_kernel,
    "lynis":        _process_lynis,
}
