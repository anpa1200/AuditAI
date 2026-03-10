import os
import stat
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import (
    HOST_ROOT, ETC_PATH, HOME_PATH, TMP_PATH, KNOWN_SUID_BINARIES
)

logger = logging.getLogger(__name__)

# Directories to scan for SUID/SGID (avoids /proc, /sys virtual filesystems)
SCAN_DIRS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
             "/usr/local/sbin", "/lib", "/usr/lib", "/opt", "/home", "/tmp",
             "/var", "/srv"]


class FilesystemScanner(BaseScanner):
    name = "filesystem"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["suid_sgid_files"] = _find_suid_sgid()
        result["world_writable_dirs"] = _find_world_writable_dirs()
        result["world_writable_files"] = _find_world_writable_files()
        result["tmp_permissions"] = _check_tmp_perms()
        result["sensitive_file_perms"] = _check_sensitive_files()
        result["unowned_files"] = _find_unowned_files()
        result["cron_perms"] = _check_cron_perms()
        result["ssh_host_key_perms"] = _check_ssh_key_perms()
        result["root_history"] = _check_root_history()
        result["writeable_path_dirs"] = _check_path_dirs()
        return result, []


def _get_host_path(path: str) -> str:
    """Convert an absolute path to its host-mounted equivalent."""
    if HOST_ROOT and HOST_ROOT != "/":
        return HOST_ROOT + path
    return path


def _find_suid_sgid() -> dict:
    suid_files = []
    sgid_files = []
    unknown_suid = []

    for scan_dir in SCAN_DIRS:
        host_dir = _get_host_path(scan_dir)
        if not os.path.isdir(host_dir):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(host_dir, followlinks=False):
                # Skip virtual filesystems
                dirnames[:] = [
                    d for d in dirnames
                    if not os.path.ismount(os.path.join(dirpath, d))
                    or os.path.join(dirpath, d) not in ["/proc", "/sys", "/dev"]
                ]
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        st = os.lstat(filepath)
                        mode = st.st_mode
                        # Convert back to original path
                        orig_path = filepath
                        if HOST_ROOT and HOST_ROOT != "/":
                            orig_path = filepath[len(HOST_ROOT):]

                        if mode & stat.S_ISUID:
                            entry = {
                                "path": orig_path,
                                "mode": oct(mode & 0o7777),
                                "owner_uid": st.st_uid,
                                "size": st.st_size,
                            }
                            suid_files.append(entry)
                            if orig_path not in KNOWN_SUID_BINARIES:
                                unknown_suid.append(entry)
                        elif mode & stat.S_ISGID and stat.S_ISREG(mode):
                            sgid_files.append({
                                "path": orig_path,
                                "mode": oct(mode & 0o7777),
                                "owner_uid": st.st_uid,
                            })
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"SUID scan failed for {host_dir}: {e}")

    return {
        "suid_count": len(suid_files),
        "sgid_count": len(sgid_files),
        "unknown_suid": unknown_suid,
        "all_suid": suid_files,
    }


def _find_world_writable_dirs() -> list[dict]:
    results = []
    skip_dirs = {"/proc", "/sys", "/dev"}

    for scan_dir in SCAN_DIRS:
        host_dir = _get_host_path(scan_dir)
        if not os.path.isdir(host_dir):
            continue
        try:
            for dirpath, dirnames, _ in os.walk(host_dir, followlinks=False):
                dirnames[:] = [
                    d for d in dirnames
                    if os.path.join(dirpath, d) not in skip_dirs
                ]
                try:
                    st = os.lstat(dirpath)
                    mode = st.st_mode
                    if stat.S_ISDIR(mode) and (mode & 0o002):
                        orig_path = dirpath
                        if HOST_ROOT and HOST_ROOT != "/":
                            orig_path = dirpath[len(HOST_ROOT):]
                        has_sticky = bool(mode & stat.S_ISVTX)
                        results.append({
                            "path": orig_path,
                            "mode": oct(mode & 0o7777),
                            "sticky_bit": has_sticky,
                            "risky": not has_sticky,
                        })
                except Exception:
                    pass
        except Exception:
            pass

    return results[:100]  # Cap


def _find_world_writable_files() -> list[dict]:
    results = []
    system_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]

    for scan_dir in system_dirs:
        host_dir = _get_host_path(scan_dir)
        if not os.path.isdir(host_dir):
            continue
        try:
            for dirpath, _, filenames in os.walk(host_dir, followlinks=False):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        st = os.lstat(filepath)
                        if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o002):
                            orig_path = filepath
                            if HOST_ROOT and HOST_ROOT != "/":
                                orig_path = filepath[len(HOST_ROOT):]
                            results.append({
                                "path": orig_path,
                                "mode": oct(st.st_mode & 0o7777),
                            })
                    except Exception:
                        pass
        except Exception:
            pass

    return results


def _check_tmp_perms() -> dict:
    result = {}
    for tmp_dir in ["/tmp", "/var/tmp", "/dev/shm"]:
        host_tmp = _get_host_path(tmp_dir)
        if os.path.exists(host_tmp):
            try:
                st = os.stat(host_tmp)
                mode = st.st_mode
                result[tmp_dir] = {
                    "mode": oct(mode & 0o7777),
                    "sticky_bit": bool(mode & stat.S_ISVTX),
                    "world_writable": bool(mode & 0o002),
                }
            except Exception as e:
                result[tmp_dir] = {"error": str(e)}
    return result


def _check_sensitive_files() -> dict:
    sensitive = {
        "/etc/passwd": 0o644,
        "/etc/shadow": 0o640,
        "/etc/gshadow": 0o640,
        "/etc/group": 0o644,
        "/etc/sudoers": 0o440,
        "/etc/crontab": 0o600,
        "/etc/ssh/sshd_config": 0o600,
        "/boot/grub/grub.cfg": 0o600,
    }
    result = {}
    for path, expected_mode in sensitive.items():
        host_path = _get_host_path(path)
        if os.path.exists(host_path):
            try:
                st = os.stat(host_path)
                actual_mode = st.st_mode & 0o777
                result[path] = {
                    "actual_mode": oct(actual_mode),
                    "expected_max_mode": oct(expected_mode),
                    "too_permissive": actual_mode > expected_mode,
                    "owner_uid": st.st_uid,
                }
            except Exception as e:
                result[path] = {"error": str(e)}
    return result


def _find_unowned_files() -> list[str]:
    """Find files owned by UIDs not in /etc/passwd."""
    known_uids = set()
    try:
        with open(f"{ETC_PATH}/passwd") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    known_uids.add(int(parts[2]))
    except Exception:
        return []

    unowned = []
    for scan_dir in ["/etc", "/usr", "/var", "/home"]:
        host_dir = _get_host_path(scan_dir)
        if not os.path.isdir(host_dir):
            continue
        try:
            for dirpath, _, filenames in os.walk(host_dir, followlinks=False):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        st = os.lstat(filepath)
                        if st.st_uid not in known_uids:
                            orig_path = filepath
                            if HOST_ROOT and HOST_ROOT != "/":
                                orig_path = filepath[len(HOST_ROOT):]
                            unowned.append(orig_path)
                            if len(unowned) >= 50:
                                return unowned
                    except Exception:
                        pass
        except Exception:
            pass
    return unowned


def _check_cron_perms() -> dict:
    result = {}
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
                  "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    for path in cron_paths:
        host_path = _get_host_path(path)
        if os.path.exists(host_path):
            try:
                st = os.stat(host_path)
                result[path] = {
                    "mode": oct(st.st_mode & 0o7777),
                    "owner_uid": st.st_uid,
                    "world_writable": bool(st.st_mode & 0o002),
                }
            except Exception:
                pass
    return result


def _check_ssh_key_perms() -> dict:
    result = {}
    ssh_dir = _get_host_path("/etc/ssh")
    if not os.path.isdir(ssh_dir):
        return result
    for fname in os.listdir(ssh_dir):
        if "key" in fname:
            full = os.path.join(ssh_dir, fname)
            try:
                st = os.stat(full)
                mode = st.st_mode & 0o777
                result[f"/etc/ssh/{fname}"] = {
                    "mode": oct(mode),
                    "is_private": "key" in fname and "pub" not in fname,
                    "too_permissive": (mode & 0o077) != 0,
                }
            except Exception:
                pass
    return result


def _check_root_history() -> dict:
    result = {}
    history_files = ["/root/.bash_history", "/root/.zsh_history", "/root/.history"]
    for path in history_files:
        host_path = _get_host_path(path)
        if os.path.exists(host_path):
            try:
                st = os.stat(host_path)
                result[path] = {
                    "mode": oct(st.st_mode & 0o777),
                    "world_readable": bool(st.st_mode & 0o004),
                    "size_bytes": st.st_size,
                }
            except Exception:
                pass
    return result


def _check_path_dirs() -> list[dict]:
    result = []
    path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    for dir_path in path_env.split(":"):
        host_dir = _get_host_path(dir_path)
        if os.path.isdir(host_dir):
            try:
                st = os.stat(host_dir)
                mode = st.st_mode
                if mode & 0o002:
                    result.append({
                        "path": dir_path,
                        "mode": oct(mode & 0o7777),
                        "world_writable": True,
                    })
            except Exception:
                pass
    return result
