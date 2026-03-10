import os
import subprocess
import glob
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import ETC_PATH, RUN_PATH, PROC_PATH

logger = logging.getLogger(__name__)


class ServicesScanner(BaseScanner):
    name = "services"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["systemd_units"] = _get_systemd_units()
        result["systemd_failed"] = _get_failed_units()
        result["listening_processes"] = _get_listening_processes()
        result["cron_jobs"] = _get_cron_jobs()
        result["docker_socket"] = _check_docker_socket()
        result["at_jobs"] = _get_at_jobs()
        result["inetd_xinetd"] = _check_inetd()
        result["init_scripts"] = _get_init_scripts()
        result["timers"] = _get_systemd_timers()
        return result, []


def _get_systemd_units() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--all",
             "--no-pager", "--no-legend", "--plain"],
            text=True, timeout=15
        )
        units = []
        for line in out.strip().splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                units.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                })
        return units
    except Exception as e:
        logger.warning(f"systemctl list-units failed: {e}")
        return []


def _get_failed_units() -> list[str]:
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--state=failed", "--no-pager",
             "--no-legend", "--plain"],
            text=True, timeout=10
        )
        return out.strip().splitlines()
    except Exception:
        return []


def _get_listening_processes() -> str:
    try:
        return subprocess.check_output(
            ["ss", "-tlnpu"], text=True, timeout=10
        )
    except Exception:
        return ""


def _get_cron_jobs() -> dict:
    result = {}
    cron_paths = [
        f"{ETC_PATH}/crontab",
        f"{ETC_PATH}/cron.d",
        f"{ETC_PATH}/cron.daily",
        f"{ETC_PATH}/cron.hourly",
        f"{ETC_PATH}/cron.weekly",
        f"{ETC_PATH}/cron.monthly",
    ]
    for path in cron_paths:
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    result[path] = f.read()
            except Exception:
                pass
        elif os.path.isdir(path):
            for entry in os.listdir(path):
                full = os.path.join(path, entry)
                try:
                    with open(full) as f:
                        result[full] = f.read()
                except Exception:
                    pass

    # User cron spool
    spool_dir = "/var/spool/cron"
    if os.path.isdir(spool_dir):
        try:
            for user in os.listdir(spool_dir):
                full = os.path.join(spool_dir, user)
                with open(full) as f:
                    result[f"spool:{user}"] = f.read()
        except Exception:
            pass

    return result


def _check_docker_socket() -> dict:
    socket_path = "/var/run/docker.sock"
    result = {"path": socket_path, "exists": False}
    if os.path.exists(socket_path):
        result["exists"] = True
        st = os.stat(socket_path)
        result["mode"] = oct(st.st_mode)
        result["owner_uid"] = st.st_uid
        result["owner_gid"] = st.st_gid
        # World-readable docker socket is a critical finding
        result["world_readable"] = bool(st.st_mode & 0o006)
    return result


def _get_at_jobs() -> list[str]:
    try:
        out = subprocess.check_output(
            ["atq"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        return out.strip().splitlines()
    except Exception:
        return []


def _check_inetd() -> dict:
    result = {}
    for name in ["inetd", "xinetd"]:
        conf = f"{ETC_PATH}/{name}.conf"
        if os.path.exists(conf):
            try:
                with open(conf) as f:
                    result[name] = f.read()
            except Exception:
                result[name] = "exists but unreadable"
    conf_d = f"{ETC_PATH}/xinetd.d"
    if os.path.isdir(conf_d):
        result["xinetd.d"] = os.listdir(conf_d)
    return result


def _get_init_scripts() -> list[str]:
    try:
        return os.listdir(f"{ETC_PATH}/init.d")
    except Exception:
        return []


def _get_systemd_timers() -> str:
    try:
        return subprocess.check_output(
            ["systemctl", "list-timers", "--all", "--no-pager"],
            text=True, timeout=10
        )
    except Exception:
        return ""
