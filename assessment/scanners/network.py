import subprocess
import socket
import logging
import re
from assessment.scanners.base import BaseScanner
from assessment.config import ETC_PATH, PROC_PATH

logger = logging.getLogger(__name__)


class NetworkScanner(BaseScanner):
    name = "network"

    def _scan(self) -> tuple[dict, list]:
        result = {}

        result["hostname"] = _get_hostname()
        result["interfaces"] = _get_interfaces()
        result["open_ports_ss"] = _get_open_ports_ss()
        result["nmap_localhost"] = _run_nmap("127.0.0.1")

        primary_ip = _get_primary_ip()
        if primary_ip and primary_ip != "127.0.0.1":
            result["nmap_primary"] = _run_nmap(primary_ip)
            result["primary_ip"] = primary_ip

        result["firewall_iptables"] = _get_iptables()
        result["firewall_nftables"] = _read_nftables()
        result["firewall_ufw"] = _read_ufw()
        result["ipv6_interfaces"] = _get_ipv6_interfaces()
        result["routing_table"] = _get_routing_table()
        result["arp_cache"] = _get_arp_cache()
        result["dns_config"] = _read_resolv_conf()
        result["hosts_file"] = _read_hosts()

        return result, []


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _get_interfaces() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["ip", "-j", "addr"], text=True, timeout=10
        )
        import json
        return json.loads(out)
    except Exception as e:
        logger.warning(f"ip addr failed: {e}")
        return []


def _get_open_ports_ss() -> str:
    try:
        return subprocess.check_output(
            ["ss", "-tlnpu"], text=True, timeout=10
        )
    except Exception as e:
        logger.warning(f"ss failed: {e}")
        return ""


def _run_nmap(target: str) -> dict:
    try:
        cmd = [
            "nmap", "-sS", "-sV", "--top-ports", "1000",
            "-T4", "--open", "-oX", "-", target
        ]
        out = subprocess.check_output(cmd, text=True, timeout=300, stderr=subprocess.DEVNULL)
        return {"xml": out, "target": target}
    except subprocess.TimeoutExpired:
        return {"error": "nmap timed out", "target": target}
    except Exception as e:
        logger.warning(f"nmap failed for {target}: {e}")
        try:
            # Fallback: TCP connect scan (no raw socket needed)
            cmd = [
                "nmap", "-sT", "--top-ports", "100",
                "-T4", "--open", "-oX", "-", target
            ]
            out = subprocess.check_output(cmd, text=True, timeout=120, stderr=subprocess.DEVNULL)
            return {"xml": out, "target": target, "note": "Fallback connect scan"}
        except Exception as e2:
            return {"error": str(e2), "target": target}


def _get_iptables() -> dict:
    result = {}
    for table in ["filter", "nat", "mangle"]:
        try:
            out = subprocess.check_output(
                ["iptables", "-t", table, "-L", "-n", "--line-numbers"],
                text=True, timeout=10, stderr=subprocess.DEVNULL
            )
            result[table] = out
        except Exception:
            pass
    try:
        result["ip6_filter"] = subprocess.check_output(
            ["ip6tables", "-L", "-n"], text=True, timeout=10, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass
    return result


def _read_nftables() -> str:
    paths = [
        f"{ETC_PATH}/nftables.conf",
        f"{ETC_PATH}/nftables.d",
    ]
    for p in paths:
        try:
            with open(p) as f:
                return f.read()
        except Exception:
            pass
    try:
        return subprocess.check_output(
            ["nft", "list", "ruleset"], text=True, timeout=10, stderr=subprocess.DEVNULL
        )
    except Exception:
        return ""


def _read_ufw() -> dict:
    result = {}
    ufw_paths = [
        f"{ETC_PATH}/ufw/user.rules",
        f"{ETC_PATH}/ufw/user6.rules",
        f"{ETC_PATH}/ufw/before.rules",
        f"{ETC_PATH}/ufw/after.rules",
    ]
    for path in ufw_paths:
        try:
            with open(path) as f:
                result[path] = f.read()
        except Exception:
            pass
    try:
        result["status"] = subprocess.check_output(
            ["ufw", "status", "verbose"], text=True, timeout=10, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass
    return result


def _get_ipv6_interfaces() -> str:
    try:
        return subprocess.check_output(
            ["ip", "-6", "addr"], text=True, timeout=10
        )
    except Exception:
        return ""


def _get_routing_table() -> str:
    try:
        return subprocess.check_output(
            ["ip", "route"], text=True, timeout=10
        )
    except Exception:
        return ""


def _get_arp_cache() -> str:
    try:
        return subprocess.check_output(
            ["arp", "-n"], text=True, timeout=10
        )
    except Exception:
        return ""


def _read_resolv_conf() -> str:
    try:
        with open(f"{ETC_PATH}/resolv.conf") as f:
            return f.read()
    except Exception:
        return ""


def _read_hosts() -> str:
    try:
        with open(f"{ETC_PATH}/hosts") as f:
            return f.read()
    except Exception:
        return ""
