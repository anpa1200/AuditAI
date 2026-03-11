# AuditAI

**AI-powered host vulnerability assessment tool running entirely inside Docker.**

AuditAI runs nine security scanner modules against your Linux host, feeds the raw findings to Claude, and produces a prioritized vulnerability report with attack chain analysis — all from a single command.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
```

> **Full write-up:** [Building a Dockerized AI-Powered Host Vulnerability Assessment Tool](https://medium.com/@1200km/building-a-dockerized-ai-powered-host-vulnerability-assessment-tool-cd6e2147ce59)

---

## How It Works

AuditAI is a three-stage pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              DOCKER CONTAINER (read-only)                │  │
│  │                                                          │  │
│  │  ┌─────────────┐   ┌────────────────┐   ┌────────────┐  │  │
│  │  │   STAGE 1   │   │    STAGE 2     │   │  STAGE 3   │  │  │
│  │  │  9 Scanner  │──▶│  Preprocessor  │──▶│   Report   │  │  │
│  │  │  Modules    │   │  + Claude AI   │   │ Generator  │  │  │
│  │  │  (parallel) │   │  (sequential)  │   │            │  │  │
│  │  └─────────────┘   └────────────────┘   └────────────┘  │  │
│  │        │                   │                  │          │  │
│  │        ▼                   ▼                  ▼          │  │
│  │  raw_output dicts   Finding[] +         HTML + .md       │  │
│  │                     attack chains       ./output/        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  /proc  /sys  /etc  /var  /home  /usr  (mounted read-only)     │
└─────────────────────────────────────────────────────────────────┘
```

**Stage 1 — Scan:** Nine modules run in parallel collecting raw host data (process table, network state, filesystem, packages, kernel parameters, etc.).

**Stage 2 — AI Analysis:** A preprocessor filters each module's raw output (60–90% size reduction), then Claude analyzes each module sequentially and performs a cross-module synthesis to identify attack chains.

**Stage 3 — Report:** Findings, attack chains, and priorities are rendered to a self-contained HTML report and Markdown file.

The container mounts the host filesystem **read-only** and uses `--pid=host` + `--network=host` to see the real process table and network state. It **cannot modify** anything on the host.

---

## Requirements

- Docker (any recent version)
- Linux host (Ubuntu/Debian recommended; other distros work)
- [Anthropic API key](https://console.anthropic.com/) — ~$0.10–0.30 per full scan on Sonnet

---

## Quick Start

**1. Install Docker** (if not already installed):

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
```

**2. Clone and run:**

```bash
git clone https://github.com/anpa1200/AuditAI.git
cd AuditAI

export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
```

`run.sh` builds the image, shows you exactly what host access it requests, asks for confirmation, then writes reports to `./output/`.

No `pip install`, no virtualenv, no dependency management on your side — everything is baked into the Docker image.

---

## Usage

```bash
# Full assessment — all 9 modules, AI analysis, all severities
./run.sh

# Skip lynis — faster (~2 min vs ~10 min), saves API cost
./run.sh --skip lynis

# Specific modules only
./run.sh --modules network,users,kernel

# No AI analysis — raw scanner output only (no API calls)
./run.sh --no-ai

# Show only HIGH and CRITICAL findings
./run.sh --severity HIGH

# Use Claude Opus for deeper attack chain reasoning
./run.sh --model claude-opus-4-6

# Verbose logging (shows preprocessor reduction stats, AI timing)
./run.sh --verbose
```

### Docker Compose

```bash
ANTHROPIC_API_KEY=sk-ant-... docker compose run assessment
```

### Direct CLI (development mode — no Docker)

```bash
# HOST_ROOT="" makes scanners read the real / instead of /host
HOST_ROOT="" python3 -m assessment.cli --modules kernel,os_hardening --no-ai
```

Useful when iterating on a scanner without rebuilding the image.

---

## What the Terminal Looks Like

```
► Running 9 scanner modules...
  Modules: network, services, os_hardening, users, processes,
           filesystem, kernel, packages, lynis

  ✓ network              12.3s
  ✓ services              0.1s
  ✓ os_hardening          0.0s
  ✓ users                 0.0s
  ✓ processes             0.2s
  ✓ filesystem           31.2s
  ✓ kernel                0.0s
  ✓ packages             15.5s
  ✓ lynis                 0.0s

► Running AI analysis (Claude)...
  Analyzing modules...
  Running synthesis...

► Generating reports...
  HTML:     ./output/report_2026-03-11T09-18-35Z.html
  Markdown: ./output/report_2026-03-11T09-18-35Z.md

╔══════════════════ SUMMARY ══════════════════╗
  Overall Risk: HIGH (67/100)
  Lynis Hardening Index: 58/100
  Findings:
    3 Critical  11 High  24 Medium  18 Low

  Top Action: Disable PasswordAuthentication in /etc/ssh/sshd_config
╚══════════════════════════════════════════════╝
```

---

## Scanner Modules

| Module | What it checks |
|--------|---------------|
| `network` | Open ports (nmap SYN scan), services binding to 0.0.0.0, firewall rules (iptables/ufw/nftables), IPv6 exposure |
| `services` | Systemd units (via filesystem fallback when inside Docker), failed services, cron jobs, docker socket permissions |
| `os_hardening` | 25+ sysctl parameters vs. secure baseline, AppArmor/SELinux, GRUB boot flags, PAM config, core dumps |
| `users` | UID 0 accounts, sudoers NOPASSWD, SSH config weaknesses, authorized keys, legacy files (.rhosts) |
| `processes` | Process capabilities (decoded from hex bitmask), deleted executables, reverse shell indicators, root processes |
| `filesystem` | SUID/SGID binaries vs. known-good baseline, world-writable system files, sensitive file permissions |
| `kernel` | CPU vulnerability mitigations (Spectre/Meltdown/etc.), kernel lockdown, BPF restrictions, loaded modules |
| `packages` | Installed packages vs. [OSV.dev](https://osv.dev/) CVE database (no API key needed), dangerous legacy packages, auto-update config |
| `lynis` | Full lynis host audit, hardening index score (0–100), warnings and suggestions |

---

## The AI Analysis

Two passes run over the scanner data:

**Pass 1 — Per-module analysis:** Each module's output goes through a preprocessor that strips known-safe baseline data (e.g. compliant sysctl params, known-safe SUID binaries, service accounts without login shells) before sending to Claude. This reduces prompt size 60–90%, eliminating token limit errors and cutting cost.

**Pass 2 — Synthesis:** A single prompt receives all module findings and is asked to identify:
- **Attack chains** — how findings combine into real exploit paths on *your specific host*
- **Top 10 priorities** — ranked by actual exploitability, not just severity label
- **Overall risk rating** — CRITICAL / HIGH / MEDIUM / LOW with justification
- **Executive summary** — non-technical prose for a system owner

---

## Report Output

Two files are written to `./output/` after each scan:

- **`report_<timestamp>.html`** — self-contained dark-theme HTML with filterable findings table, attack chain cards, and collapsible module sections. No internet connection required to open.
- **`report_<timestamp>.md`** — Markdown version for archiving, tickets, or plain-text sharing.

### Report Sections

| Section | Description |
|---------|-------------|
| Risk badge | CRITICAL / HIGH / MEDIUM / LOW with 0–100 score |
| Immediate actions | 3–5 things to fix today, in order |
| Attack chains | Multi-step exploit scenarios specific to your host |
| Top 10 priorities | Findings ranked by real exploitability |
| Module sections | Collapsible, each with risk score, evidence, and remediation commands |
| Lynis appendix | Full hardening index and raw lynis suggestions |

---

## Docker Flags Explained

| Flag | Why it's needed |
|------|----------------|
| `--pid=host` | Without this, `/proc` only shows container PIDs. Needed to enumerate all host processes, read capabilities, and resolve executable paths. |
| `--network=host` | Places the container in the host's network namespace. nmap sees actual interfaces and real IP addresses — without this it only sees the container's virtual eth0. |
| `--cap-add=NET_RAW` | nmap SYN scans (`-sS`) require raw socket access to craft TCP packets. Without it, nmap falls back to slower TCP connect scans. |
| `--cap-add=NET_ADMIN` | Required to read iptables/netfilter state from inside the container. |
| `--cap-add=SYS_PTRACE` | Needed to follow `/proc/<pid>/exe` symlinks and read process memory maps. |
| `--cap-add=AUDIT_READ` | Allows reading the kernel audit log for privilege escalation records. |
| `-v /:/host:ro` | Bind-mounts the entire host root at `/host`, read-only. Gives access to `/etc`, `/var`, `/usr`, `/home`. |
| `-v /proc:/host/proc:ro` | `/proc` is a virtual filesystem not captured by the `/` mount. Must be mounted separately. |
| `-v /sys:/host/sys:ro` | Same as `/proc`. Contains CPU vulnerability data, security module status, kernel parameters. |

`--privileged` is intentionally **not used**. The container operates within normal Linux namespace boundaries and cannot modify host kernel state.

---

## Error Handling

| Error | Behavior |
|-------|----------|
| Scanner crash (nmap timeout, permission denied) | Records error in report, continues other modules |
| API rate limit (429) | Exponential backoff: 15s → 30s → 60s → 120s, up to 4 retries |
| Insufficient API credits (400) | Fails immediately with actionable message, suggests `--no-ai` |
| JSON decode error in AI response | Retries up to 4 times, records empty findings on final failure |
| `systemctl` not found (Docker) | Falls back to reading `.service` files from host filesystem |

---

## Security Notes

- All host mounts are **read-only**. The only writable path is `./output/`.
- Scan data is sent to the Anthropic API for AI analysis. Use `--no-ai` for air-gapped or regulated environments.
- Reports contain detailed host configuration — treat them like passwords. Don't commit to public repos.
- This tool is for **authorized use only** on systems you own or have permission to assess.

---

## Project Structure

```
AuditAI/
├── Dockerfile
├── docker-compose.yml
├── run.sh                       # Host-side launcher with consent prompt
├── requirements.txt
└── assessment/
    ├── cli.py                   # Click CLI — entry point, orchestrates all stages
    ├── config.py                # HOST_ROOT paths, sysctl baselines, SUID whitelist
    ├── models.py                # Finding, ModuleResult, AttackChain, Report dataclasses
    ├── runner.py                # Stage 1 — parallel scanner execution
    ├── scanners/
    │   ├── base.py              # Abstract BaseScanner with error isolation + timing
    │   ├── network.py           # nmap, ss, iptables, ufw, nftables, IPv6
    │   ├── services.py          # systemd units (with Docker filesystem fallback)
    │   ├── os_hardening.py      # sysctl, AppArmor, SELinux, GRUB, PAM
    │   ├── users.py             # passwd, shadow, sudoers, SSH keys
    │   ├── processes.py         # /proc enumeration, capability decoding
    │   ├── filesystem.py        # SUID/SGID, world-writable, sensitive perms
    │   ├── kernel.py            # CPU vulns, lockdown, modules
    │   ├── packages.py          # dpkg + OSV.dev CVE API
    │   └── lynis_wrapper.py     # lynis audit + report.dat parser
    ├── ai/
    │   ├── client.py            # Anthropic SDK wrapper, retry + billing error handling
    │   ├── preprocessor.py      # Per-module data filter (60–90% size reduction)
    │   ├── prompts.py           # All prompt templates (edit to tune AI quality)
    │   └── analyzer.py          # Stage 2 — sequential module analysis + synthesis
    └── reports/
        ├── html.py              # Self-contained dark-theme HTML (no CDN)
        └── markdown.py          # Markdown report generator
```

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

The AI analysis, preprocessor hook, report generation, and CLI integration are automatic.

To also add preprocessor logic for your module, add a handler to `assessment/ai/preprocessor.py`:

```python
def _process_my_module(raw: dict) -> dict:
    # Return only the high-signal subset of raw
    return {"key_finding": raw.get("key_finding")}

_HANDLERS["my_module"] = _process_my_module
```

---

## Read More

Full architecture deep-dive, design decisions, and real findings from running this on a live machine:

**[Building a Dockerized AI-Powered Host Vulnerability Assessment Tool](https://medium.com/@1200km/building-a-dockerized-ai-powered-host-vulnerability-assessment-tool-cd6e2147ce59)**

---

## License

MIT
