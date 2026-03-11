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
    """List systemd service units via systemctl, falling back to filesystem scan
    when running inside a Docker container where systemctl is unavailable."""
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
        logger.warning(f"systemctl list-units failed: {e} — reading unit files from host filesystem")
        return _get_systemd_units_from_fs()


def _get_systemd_units_from_fs() -> list[dict]:
    """Read installed systemd unit files from host filesystem (Docker fallback)."""
    from assessment.config import HOST_ROOT
    units = []
    seen: set = set()

    # Unit file locations (prefer host-mounted paths)
    dirs_relative = [
        "etc/systemd/system",
        "lib/systemd/system",
        "usr/lib/systemd/system",
    ]
    search_dirs = [
        os.path.join(HOST_ROOT, d) if HOST_ROOT else os.path.join("/", d)
        for d in dirs_relative
    ]

    # Detect enabled units via .wants/ symlink directories
    enabled_units: set = set()
    for base in search_dirs:
        for wants_dir in glob.glob(os.path.join(base, "*.wants")):
            try:
                for entry in os.listdir(wants_dir):
                    enabled_units.add(entry)
            except Exception:
                pass

    # Enumerate .service files
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        try:
            for fname in os.listdir(search_dir):
                if not fname.endswith(".service") or fname in seen:
                    continue
                seen.add(fname)
                units.append({
                    "unit": fname,
                    "load": "loaded",
                    "active": "unknown",
                    "sub": "unknown",
                    "enabled": fname in enabled_units,
                })
        except Exception as e:
            logger.debug(f"Could not list {search_dir}: {e}")

    # Try to detect active units from runtime state
    run_units = os.path.join(HOST_ROOT, "run/systemd/units") if HOST_ROOT else "/run/systemd/units"
    if os.path.isdir(run_units):
        try:
            active_names = {f for f in os.listdir(run_units) if f.endswith(".service")}
            for u in units:
                if u["unit"] in active_names:
                    u["active"] = "active"
        except Exception:
            pass

    return units


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


def _get_systemd_timers() -> list[str]:
    try:
        out = subprocess.check_output(
            ["systemctl", "list-timers", "--all", "--no-pager"],
            text=True, timeout=10
        )
        return out.strip().splitlines()
    except Exception:
        # Fallback: find .timer unit files on host filesystem
        from assessment.config import HOST_ROOT
        timers = []
        dirs_relative = ["etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system"]
        for rel in dirs_relative:
            d = os.path.join(HOST_ROOT, rel) if HOST_ROOT else os.path.join("/", rel)
            if os.path.isdir(d):
                try:
                    timers += [f for f in os.listdir(d) if f.endswith(".timer")]
                except Exception:
                    pass
        return timers
