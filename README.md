# AuditAI

**AI-powered host vulnerability assessment tool running entirely inside Docker.**

AuditAI runs nine security scanner modules against your Linux host, feeds the raw findings to Claude, and produces a prioritized vulnerability report with attack chain analysis — all from a single command.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
```

---

## How It Works

```
Docker container (read-only host access)
        │
        ├── network scanner      ─┐
        ├── services scanner      │
        ├── os_hardening scanner  │  parallel
        ├── users scanner         │  execution
        ├── processes scanner     │
        ├── filesystem scanner    │
        ├── kernel scanner        │
        ├── packages scanner     ─┘
        └── lynis wrapper
                │
                ▼
        Claude AI Analysis
        (per-module + synthesis)
                │
                ▼
        HTML + Markdown Report
        ./output/
```

The container mounts the host filesystem read-only (`/:/host:ro`) and uses `--pid=host` + `--network=host` to see the real process table and network state. It **cannot modify** anything on the host.

---

## Requirements

- Docker
- Linux host (Ubuntu/Debian recommended)
- [Anthropic API key](https://console.anthropic.com/)

---

## Quick Start

```bash
git clone https://github.com/anpa1200/AuditAI.git
cd AuditAI

export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
```

`run.sh` will build the image, show you exactly what host access it requests, ask for confirmation, then write reports to `./output/`.

---

## Usage

```bash
# Full assessment (all 9 modules + AI analysis)
./run.sh

# Skip lynis — faster, saves ~5 minutes
./run.sh --skip lynis

# Specific modules only
./run.sh --modules network,users,kernel

# No AI analysis — raw scanner output only
./run.sh --no-ai

# Filter findings by minimum severity
./run.sh --severity HIGH

# Choose Claude model
./run.sh --model claude-opus-4-6

# Verbose logging
./run.sh --verbose
```

### Docker Compose

```bash
ANTHROPIC_API_KEY=sk-ant-... docker compose run assessment
```

### Direct CLI (inside container or with HOST_ROOT="")

```bash
python3 -m assessment.cli --modules network,users --severity MEDIUM
```

---

## Scanner Modules

| Module | What it checks |
|--------|---------------|
| `network` | Open ports (nmap), services binding to 0.0.0.0, firewall rules (iptables/ufw/nftables), IPv6 exposure |
| `services` | Systemd units, failed services, cron jobs, docker socket permissions |
| `os_hardening` | 25+ sysctl parameters, AppArmor/SELinux, GRUB boot flags, PAM config, core dumps |
| `users` | UID 0 accounts, sudoers NOPASSWD, SSH config, authorized keys, legacy files (.rhosts) |
| `processes` | Process capabilities, deleted executables, reverse shell indicators, root processes |
| `filesystem` | SUID/SGID binaries, world-writable system files, sensitive file permissions |
| `kernel` | CPU vulnerability mitigations (Spectre/Meltdown), kernel lockdown, loaded modules |
| `packages` | Installed packages vs. OSV.dev CVE database, dangerous packages, auto-update config |
| `lynis` | Full lynis host audit, hardening index score (0–100), warnings and suggestions |

---

## Report Output

Two files are written to `./output/` after each scan:

- **`report_<timestamp>.html`** — self-contained dark-theme HTML with filterable findings table, attack chain cards, and module sections. No internet connection required to open.
- **`report_<timestamp>.md`** — Markdown version for archiving or sharing as plain text.

### Report sections

- Overall risk rating (CRITICAL / HIGH / MEDIUM / LOW) with score
- Executive summary (AI-generated, non-technical)
- Immediate action items
- Attack chain analysis — how findings combine into real exploit paths
- Top 10 priorities ranked by exploitability
- Per-module findings with evidence and remediation commands
- Lynis hardening index and raw suggestions

---

## Docker Flags Explained

| Flag | Reason |
|------|--------|
| `--pid=host` | Access the real host process table via `/proc` |
| `--network=host` | nmap scans the host's real network interfaces |
| `--cap-add=NET_RAW` | nmap SYN scans require raw socket access |
| `--cap-add=NET_ADMIN` | Read firewall rules |
| `--cap-add=SYS_PTRACE` | Read `/proc/<pid>/exe` for process analysis |
| `--cap-add=AUDIT_READ` | Read audit logs |
| `-v /:/host:ro` | Host filesystem, read-only |
| `-v /proc:/host/proc:ro` | Host process table (virtual fs, mounted separately) |
| `-v /sys:/host/sys:ro` | Kernel/hardware info (virtual fs, mounted separately) |

`--privileged` is intentionally **not used**. The container cannot write to the host.

---

## Security Notes

- All host mounts are **read-only**. The only writable path is `./output/`.
- Scan data is sent to the Anthropic API for AI analysis. Use `--no-ai` for air-gapped or regulated environments.
- Reports contain detailed host configuration — keep them private.
- This tool is for **authorized use only** on systems you own or have permission to assess.

---

## Adding a Scanner Module

```python
# assessment/scanners/my_module.py
from assessment.scanners.base import BaseScanner

class MyScanner(BaseScanner):
    name = "my_module"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["data"] = collect_something()
        return result, []  # AI identifies findings from raw data
```

Register in `assessment/scanners/__init__.py`:

```python
from assessment.scanners.my_module import MyScanner

ALL_SCANNERS = {
    ...
    "my_module": MyScanner,
}
```

---

## Project Structure

```
AuditAI/
├── Dockerfile
├── docker-compose.yml
├── run.sh                      # Host-side launcher
├── requirements.txt
└── assessment/
    ├── cli.py                  # Click CLI entry point
    ├── config.py               # Paths, constants, sysctl baseline
    ├── models.py               # Finding, ModuleResult, Report dataclasses
    ├── runner.py               # Scanner orchestration
    ├── scanners/               # 9 scanner modules
    ├── ai/                     # Claude client, prompts, analyzer
    └── reports/                # HTML + Markdown generators
```

---

## License

MIT
