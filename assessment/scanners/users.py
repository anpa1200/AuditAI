import os
import subprocess
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import ETC_PATH, HOME_PATH

logger = logging.getLogger(__name__)


class UsersScanner(BaseScanner):
    name = "users"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["passwd"] = _read_passwd()
        result["shadow_permissions"] = _check_shadow_perms()
        result["sudo_config"] = _read_sudo_config()
        result["groups"] = _read_groups()
        result["ssh_config"] = _read_ssh_server_config()
        result["user_ssh_keys"] = _check_user_ssh_keys()
        result["legacy_files"] = _check_legacy_files()
        result["logged_in_users"] = _get_logged_in()
        result["last_logins"] = _get_last_logins()
        result["failed_logins"] = _get_failed_logins()
        result["password_policy"] = _check_password_policy()
        result["su_restrictions"] = _check_su_restrictions()
        return result, []


def _read_passwd() -> list[dict]:
    users = []
    try:
        with open(f"{ETC_PATH}/passwd") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) >= 7:
                    users.append({
                        "username": parts[0],
                        "uid": int(parts[2]) if parts[2].isdigit() else parts[2],
                        "gid": int(parts[3]) if parts[3].isdigit() else parts[3],
                        "gecos": parts[4],
                        "home": parts[5],
                        "shell": parts[6],
                        "has_login_shell": parts[6] not in [
                            "/sbin/nologin", "/usr/sbin/nologin",
                            "/bin/false", "/dev/null", ""
                        ],
                    })
    except Exception as e:
        logger.warning(f"Failed to read passwd: {e}")
    return users


def _check_shadow_perms() -> dict:
    shadow_path = f"{ETC_PATH}/shadow"
    result = {"path": shadow_path}
    try:
        st = os.stat(shadow_path)
        mode = st.st_mode & 0o777
        result["mode"] = oct(mode)
        result["owner_uid"] = st.st_uid
        result["world_readable"] = bool(mode & 0o004)
        result["group_readable"] = bool(mode & 0o040)
        # Read shadow to check for empty passwords or locked accounts
        try:
            with open(shadow_path) as f:
                entries = []
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 9:
                        entries.append({
                            "username": parts[0],
                            "hash_type": parts[1][:3] if len(parts[1]) > 3 else parts[1],
                            "empty_password": parts[1] == "",
                            "locked": parts[1].startswith("!") or parts[1].startswith("*"),
                            "last_change": parts[2],
                            "max_days": parts[4],
                            "expire": parts[8],
                        })
            result["entries"] = entries
        except PermissionError:
            result["readable"] = False
    except Exception as e:
        result["error"] = str(e)
    return result


def _read_sudo_config() -> dict:
    result = {}
    sudoers_path = f"{ETC_PATH}/sudoers"
    try:
        with open(sudoers_path) as f:
            result["sudoers"] = f.read()
    except Exception:
        result["sudoers"] = "unreadable"

    sudoers_d = f"{ETC_PATH}/sudoers.d"
    if os.path.isdir(sudoers_d):
        for fname in os.listdir(sudoers_d):
            full = os.path.join(sudoers_d, fname)
            try:
                with open(full) as f:
                    result[f"sudoers.d/{fname}"] = f.read()
            except Exception:
                pass
    return result


def _read_groups() -> list[dict]:
    groups = []
    try:
        with open(f"{ETC_PATH}/group") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    members = parts[3].split(",") if parts[3] else []
                    groups.append({
                        "name": parts[0],
                        "gid": parts[2],
                        "members": members,
                    })
    except Exception as e:
        logger.warning(f"Failed to read group: {e}")
    return groups


def _read_ssh_server_config() -> dict:
    result = {}
    paths = [
        f"{ETC_PATH}/ssh/sshd_config",
        f"{ETC_PATH}/ssh/sshd_config.d",
    ]
    for path in paths:
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    config_lines = {}
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                config_lines[parts[0].lower()] = parts[1]
                    result["sshd_config"] = config_lines
            except Exception as e:
                result["sshd_config_error"] = str(e)
        elif os.path.isdir(path):
            for fname in os.listdir(path):
                full = os.path.join(path, fname)
                try:
                    with open(full) as f:
                        result[f"sshd_config.d/{fname}"] = f.read()
                except Exception:
                    pass
    return result


def _check_user_ssh_keys() -> dict:
    result = {}
    # Check root
    root_ssh = "/root/.ssh"
    if os.path.isdir(root_ssh):
        auth_keys = os.path.join(root_ssh, "authorized_keys")
        if os.path.exists(auth_keys):
            try:
                with open(auth_keys) as f:
                    keys = f.read().strip().splitlines()
                result["root_authorized_keys"] = {
                    "count": len([k for k in keys if k and not k.startswith("#")]),
                    "keys": keys,
                }
            except Exception:
                result["root_authorized_keys"] = "exists but unreadable"

    # Check home directories
    try:
        if os.path.isdir(HOME_PATH):
            home_base = HOME_PATH
        else:
            home_base = "/home"
        for user_dir in os.listdir(home_base):
            auth_keys = os.path.join(home_base, user_dir, ".ssh", "authorized_keys")
            if os.path.exists(auth_keys):
                try:
                    with open(auth_keys) as f:
                        keys = f.read().strip().splitlines()
                    result[f"{user_dir}_authorized_keys"] = {
                        "count": len([k for k in keys if k and not k.startswith("#")]),
                    }
                except Exception:
                    pass
    except Exception:
        pass
    return result


def _check_legacy_files() -> dict:
    result = {}
    legacy_files = [".rhosts", ".netrc", ".shosts"]
    check_dirs = ["/root"]
    try:
        if os.path.isdir(HOME_PATH):
            for d in os.listdir(HOME_PATH):
                check_dirs.append(os.path.join(HOME_PATH, d))
        else:
            for d in os.listdir("/home"):
                check_dirs.append(os.path.join("/home", d))
    except Exception:
        pass

    for d in check_dirs:
        for f in legacy_files:
            full = os.path.join(d, f)
            if os.path.exists(full):
                result[full] = "EXISTS"
    return result


def _get_logged_in() -> str:
    try:
        return subprocess.check_output(["who"], text=True, timeout=5)
    except Exception:
        return ""


def _get_last_logins() -> str:
    try:
        return subprocess.check_output(
            ["last", "-n", "20"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except Exception:
        return ""


def _get_failed_logins() -> str:
    try:
        return subprocess.check_output(
            ["lastb", "-n", "20"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except Exception:
        # Try parsing auth.log
        auth_log = f"{ETC_PATH}/../var/log/auth.log"
        try:
            out = subprocess.check_output(
                ["grep", "-i", "failed", auth_log, "-m", "50"],
                text=True, timeout=5
            )
            return out
        except Exception:
            return ""


def _check_password_policy() -> dict:
    result = {}
    # Check pwquality
    pwquality_path = f"{ETC_PATH}/security/pwquality.conf"
    if os.path.exists(pwquality_path):
        try:
            with open(pwquality_path) as f:
                result["pwquality"] = f.read()
        except Exception:
            pass
    # Check pam_cracklib
    common_password = f"{ETC_PATH}/pam.d/common-password"
    if os.path.exists(common_password):
        try:
            with open(common_password) as f:
                result["common_password"] = f.read()
        except Exception:
            pass
    return result


def _check_su_restrictions() -> dict:
    result = {}
    su_pam = f"{ETC_PATH}/pam.d/su"
    if os.path.exists(su_pam):
        try:
            with open(su_pam) as f:
                result["su_pam"] = f.read()
        except Exception:
            pass
    # Check wheel group usage
    group_su = f"{ETC_PATH}/group"
    try:
        with open(group_su) as f:
            for line in f:
                if line.startswith("wheel:") or line.startswith("sudo:"):
                    result[line.split(":")[0]] = line.strip()
    except Exception:
        pass
    return result
