import os

HOST_ROOT = os.environ.get("HOST_ROOT", "/host")
PROC_PATH = f"{HOST_ROOT}/proc"
SYS_PATH = f"{HOST_ROOT}/sys"
ETC_PATH = f"{HOST_ROOT}/etc"
VAR_PATH = f"{HOST_ROOT}/var"
HOME_PATH = f"{HOST_ROOT}/home"
USR_PATH = f"{HOST_ROOT}/usr"
BIN_PATH = f"{HOST_ROOT}/bin"
SBIN_PATH = f"{HOST_ROOT}/sbin"
LIB_PATH = f"{HOST_ROOT}/lib"
TMP_PATH = f"{HOST_ROOT}/tmp"
BOOT_PATH = f"{HOST_ROOT}/boot"
RUN_PATH = f"{HOST_ROOT}/run"

OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/output")

DEFAULT_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# Severity order for sorting/filtering
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Known-good SUID binaries (common baseline)
KNOWN_SUID_BINARIES = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/pkexec", "/usr/bin/at", "/usr/bin/crontab", "/usr/bin/wall",
    "/usr/bin/write", "/usr/bin/ssh-agent", "/usr/sbin/pam_timestamp_check",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping",
    "/sbin/unix_chkpwd",
}

# Dangerous packages that should not be installed on servers
DANGEROUS_PACKAGES = [
    "telnetd", "telnet-server", "rsh-server", "rsh-client",
    "talk", "talkd", "ntalk", "tftp", "atftpd", "tftpd",
    "xinetd", "nis", "yp-tools", "ypbind", "ypserv",
    "rsh", "rlogin", "rcp",
]

# Sysctl parameters: {param: (secure_value, description)}
SYSCTL_CHECKS = {
    "kernel.randomize_va_space": (2, "ASLR full randomization"),
    "kernel.dmesg_restrict": (1, "Restrict dmesg to privileged users"),
    "kernel.kptr_restrict": (2, "Hide kernel pointers from unprivileged users"),
    "kernel.yama.ptrace_scope": (1, "Restrict ptrace to parent processes"),
    "kernel.core_uses_pid": (1, "Append PID to core dump files"),
    "kernel.sysrq": (0, "Disable magic SysRq key"),
    "fs.suid_dumpable": (0, "Disable core dumps for SUID programs"),
    "fs.protected_hardlinks": (1, "Restrict hardlink creation"),
    "fs.protected_symlinks": (1, "Restrict symlink following"),
    "net.ipv4.ip_forward": (0, "Disable IPv4 forwarding (unless router)"),
    "net.ipv4.conf.all.rp_filter": (1, "Enable reverse path filtering"),
    "net.ipv4.conf.default.rp_filter": (1, "Enable reverse path filtering (default)"),
    "net.ipv4.conf.all.accept_redirects": (0, "Ignore ICMP redirects"),
    "net.ipv4.conf.default.accept_redirects": (0, "Ignore ICMP redirects (default)"),
    "net.ipv4.conf.all.send_redirects": (0, "Disable sending ICMP redirects"),
    "net.ipv4.conf.all.accept_source_route": (0, "Disable source routing"),
    "net.ipv4.conf.all.log_martians": (1, "Log martian packets"),
    "net.ipv4.tcp_syncookies": (1, "Enable TCP SYN cookies"),
    "net.ipv4.icmp_echo_ignore_broadcasts": (1, "Ignore ICMP broadcast echo"),
    "net.ipv4.icmp_ignore_bogus_error_responses": (1, "Ignore bogus ICMP error responses"),
    "net.ipv6.conf.all.accept_redirects": (0, "Ignore IPv6 ICMP redirects"),
    "net.ipv6.conf.default.accept_redirects": (0, "Ignore IPv6 ICMP redirects (default)"),
    "net.ipv6.conf.all.accept_ra": (0, "Disable IPv6 router advertisements"),
}
