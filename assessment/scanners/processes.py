import os
import subprocess
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import PROC_PATH

logger = logging.getLogger(__name__)

# Capability bitmask names
CAP_NAMES = {
    0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER", 4: "CAP_FSETID", 5: "CAP_KILL", 6: "CAP_SETGID",
    7: "CAP_SETUID", 8: "CAP_SETPCAP", 9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE", 11: "CAP_NET_BROADCAST", 12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW", 14: "CAP_IPC_LOCK", 15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE", 17: "CAP_SYS_RAWIO", 18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE", 20: "CAP_SYS_PACCT", 21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT", 23: "CAP_SYS_NICE", 24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME", 26: "CAP_SYS_TTY_CONFIG", 27: "CAP_MKNOD",
    28: "CAP_LEASE", 29: "CAP_AUDIT_WRITE", 30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP", 32: "CAP_MAC_OVERRIDE", 33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG", 35: "CAP_WAKE_ALARM", 36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ", 38: "CAP_PERFMON", 39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


class ProcessesScanner(BaseScanner):
    name = "processes"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        processes = _enumerate_processes()
        result["total_process_count"] = len(processes)
        result["root_processes"] = [p for p in processes if p.get("uid") == 0]
        result["privileged_processes"] = [
            p for p in processes if p.get("capabilities")
        ]
        result["zombie_processes"] = [
            p for p in processes if p.get("state") == "Z"
        ]
        result["processes_with_network"] = _get_network_processes()
        result["processes_in_tmp"] = [
            p for p in processes
            if p.get("exe", "").startswith("/tmp") or
               p.get("exe", "").startswith("/dev/shm")
        ]
        result["suspicious_processes"] = _find_suspicious(processes)
        result["process_list"] = processes[:200]  # Cap for token limit
        return result, []


def _enumerate_processes() -> list[dict]:
    processes = []
    try:
        proc_base = PROC_PATH
        for pid_str in os.listdir(proc_base):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            proc = {"pid": pid}
            proc_dir = os.path.join(proc_base, pid_str)

            # Read status
            try:
                with open(os.path.join(proc_dir, "status")) as f:
                    for line in f:
                        if line.startswith("Name:"):
                            proc["name"] = line.split(":", 1)[1].strip()
                        elif line.startswith("State:"):
                            proc["state"] = line.split(":", 1)[1].strip()[0]
                        elif line.startswith("Uid:"):
                            uids = line.split(":", 1)[1].strip().split()
                            proc["uid"] = int(uids[0]) if uids else -1
                            proc["euid"] = int(uids[1]) if len(uids) > 1 else -1
                        elif line.startswith("Gid:"):
                            gids = line.split(":", 1)[1].strip().split()
                            proc["gid"] = int(gids[0]) if gids else -1
                        elif line.startswith("CapEff:"):
                            cap_hex = line.split(":", 1)[1].strip()
                            cap_int = int(cap_hex, 16)
                            if cap_int > 0:
                                caps = [
                                    CAP_NAMES[i] for i in range(41)
                                    if cap_int & (1 << i)
                                ]
                                proc["capabilities"] = caps
            except Exception:
                pass

            # Read cmdline
            try:
                with open(os.path.join(proc_dir, "cmdline"), "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                    proc["cmdline"] = cmdline[:200]
            except Exception:
                pass

            # Read exe symlink
            try:
                proc["exe"] = os.readlink(os.path.join(proc_dir, "exe"))
            except Exception:
                pass

            # Check if exe is deleted
            try:
                exe_link = os.path.join(proc_dir, "exe")
                target = os.readlink(exe_link)
                proc["exe_deleted"] = "(deleted)" in target
            except Exception:
                pass

            if proc.get("name"):
                processes.append(proc)

    except Exception as e:
        logger.warning(f"Process enumeration failed: {e}")

    return processes


def _get_network_processes() -> str:
    try:
        return subprocess.check_output(
            ["ss", "-tlnpu"], text=True, timeout=10
        )
    except Exception:
        return ""


def _find_suspicious(processes: list[dict]) -> list[dict]:
    suspicious = []
    suspicious_names = {
        "nc", "netcat", "ncat", "bash", "sh", "python", "perl", "ruby",
        "php", "wget", "curl", "socat",
    }

    for p in processes:
        reasons = []
        name = p.get("name", "").lower()
        exe = p.get("exe", "")
        cmdline = p.get("cmdline", "")

        # Deleted executable
        if p.get("exe_deleted"):
            reasons.append("executable deleted from disk")

        # Shell in unusual location
        if name in {"bash", "sh", "zsh", "dash"} and p.get("uid") == 0:
            if "/sbin/" not in exe and "/bin/" not in exe and exe:
                reasons.append(f"root shell from unusual path: {exe}")

        # Process in /tmp or /dev/shm
        if exe.startswith("/tmp") or exe.startswith("/dev/shm"):
            reasons.append(f"executable from writable temp dir: {exe}")

        # Network tools running as root
        if name in suspicious_names and p.get("uid") == 0 and p.get("capabilities"):
            reasons.append("network/shell tool running with capabilities")

        # Reverse shell indicators in cmdline
        if any(indicator in cmdline.lower() for indicator in [
            "/dev/tcp", "/dev/udp", "bash -i", "bash -c", "0>&1", ">&2",
            "exec 5<>", "socat", "mkfifo",
        ]):
            reasons.append("potential reverse shell indicators in cmdline")

        if reasons:
            suspicious.append({**p, "reasons": reasons})

    return suspicious
