# Building a Dockerized AI-Powered Host Vulnerability Assessment Tool

## How I automated security auditing with Claude, Python, and Docker — and what it found on my own machine

---

Security assessments are expensive, time-consuming, and often reserved for enterprise environments with dedicated teams. But what if you could run a comprehensive vulnerability scan of your own Linux host in under 10 minutes, get AI-analyzed findings ranked by real exploitability, and receive a professional report — all from a single command?

That's exactly what I built. This article walks through the architecture, design decisions, and how to run it yourself.

---

## Table of Contents

1. [The Problem with Traditional Host Auditing](#the-problem-with-traditional-host-auditing)
2. [Getting Started](#getting-started)
3. [Architecture Overview](#architecture-overview)
4. [The Nine Scanner Modules](#the-nine-scanner-modules)
5. [The AI Layer](#the-ai-layer)
6. [The Report](#the-report)
7. [What It Found on My Machine](#what-it-found-on-my-machine)
8. [Security Considerations](#security-considerations)
9. [Extending the Tool](#extending-the-tool)
10. [What's Next](#whats-next)
11. [Conclusion](#conclusion)

---

## The Problem with Traditional Host Auditing

Most security tools solve one specific problem. `nmap` scans ports. `lynis` checks hardening. `chkrootkit` looks for rootkits. You end up running five different tools, staring at raw text output, and trying to manually correlate: *"If this port is open AND this service runs as root AND there's a SUID binary in /tmp — does that create an attack chain?"*

That correlation step is exactly where human error creeps in, and where AI genuinely helps.

The tool I built — **AuditAI** — runs nine scanner modules in parallel, feeds their output to Claude, and gets back:

- Findings with severity ratings grounded in *actual evidence* from your system
- Attack chain analysis showing how findings combine into real exploits
- A prioritized top-10 list based on your specific configuration
- A self-contained HTML report you can open in any browser

---

## Getting Started

**Prerequisites:** Docker, an Anthropic API key, and a Linux host.

```bash
git clone https://github.com/anpa1200/AuditAI.git
cd AuditAI

export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
```

The script will:

1. Build the Docker image
2. Show you exactly what host access it will request
3. Ask for confirmation before running
4. Write reports to `./output/`

**Common options:**

```bash
# Skip lynis (saves ~5 minutes on first run)
./run.sh --skip lynis

# Only scan network and users, no AI analysis
./run.sh --modules network,users --no-ai

# Only show HIGH and above findings
./run.sh --severity HIGH

# Use a specific Claude model
./run.sh --model claude-opus-4-6
```

---

## Architecture Overview

### The Big Picture

AuditAI is structured as a three-stage pipeline. Each stage is a clean handoff — scanners know nothing about AI, the AI layer knows nothing about report templates, and the report layer just renders a `Report` dataclass.

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOST MACHINE                                │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              DOCKER CONTAINER (read-only)                │  │
│  │                                                          │  │
│  │  ┌─────────────┐    ┌──────────────┐    ┌────────────┐  │  │
│  │  │   STAGE 1   │    │   STAGE 2    │    │  STAGE 3   │  │  │
│  │  │             │    │              │    │            │  │  │
│  │  │  9 Scanner  │───▶│  Claude AI   │───▶│   Report   │  │  │
│  │  │  Modules    │    │  Analysis    │    │ Generator  │  │  │
│  │  │  (parallel) │    │  (parallel)  │    │            │  │  │
│  │  └─────────────┘    └──────────────┘    └────────────┘  │  │
│  │         │                  │                   │         │  │
│  │         ▼                  ▼                   ▼         │  │
│  │   ModuleResult[]    Finding[] +          HTML + .md      │  │
│  │   raw_output dicts  attack chains        ./output/       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  /proc  /sys  /etc  /var  /home  /usr  (mounted read-only)     │
└─────────────────────────────────────────────────────────────────┘
```

### Why Docker?

Running security tooling directly on a host is messy — it means installing nmap, lynis, Python dependencies, and dealing with version conflicts across distributions. Docker gives you a clean, reproducible environment with all tools pre-installed, pinned to known versions.

The bigger advantage is **isolation without losing visibility**. The trick is giving the container *read-only* access to the host system it's assessing through a precise set of Docker flags:

```bash
docker run --rm \
  --pid=host \
  --network=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_PTRACE \
  --cap-add=AUDIT_READ \
  -v /:/host:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /var/log:/host/var/log:ro \
  -v ./output:/output \
  auditai:latest
```

Each flag exists for a specific reason — none are added "just in case":

| Flag | Why it's needed |
|------|----------------|
| `--pid=host` | Without this, `/proc` only shows container PIDs. We need the full host process table to enumerate all running processes, read their capabilities, and inspect their executables. |
| `--network=host` | Places the container in the host's network namespace. nmap then scans from the real host's perspective — it sees actual interfaces, real IP addresses, and the genuine socket state. Without this, nmap would only see the container's virtual `eth0`. |
| `--cap-add=NET_RAW` | nmap SYN scans (`-sS`) require raw socket access to craft TCP packets manually. Without this capability, nmap falls back to full TCP connect scans (`-sT`) which are slower, noisier, and miss half-open ports. |
| `--cap-add=NET_ADMIN` | Required to read iptables rules and netfilter state from inside the container. |
| `--cap-add=SYS_PTRACE` | Needed to follow `/proc/<pid>/exe` symlinks and read memory maps of running processes. Without it, the processes scanner can enumerate PIDs but can't resolve what binary is running. |
| `--cap-add=AUDIT_READ` | Allows reading the kernel audit log, which records privilege escalations and security policy violations. |
| `-v /:/host:ro` | Bind-mounts the entire host root filesystem at `/host` inside the container, read-only. This gives scanners access to `/etc`, `/var`, `/usr`, `/home`, and everything else — without any write access. |
| `-v /proc:/host/proc:ro` | `/proc` is a virtual filesystem generated by the kernel on-demand. It is **not** captured by the `/` bind mount above. It must be mounted separately for the processes and kernel scanners to work. |
| `-v /sys:/host/sys:ro` | Same reason as `/proc`. Contains kernel hardware info, security module status, CPU vulnerability data, and network stack parameters. |

The container runs as root internally — required for raw socket nmap and `/proc` reads — but `--privileged` is explicitly **not** used. Without `--privileged`, the container still operates within Linux namespace boundaries and cannot modify host kernel parameters, load kernel modules, or escape via device access.

### The Path Convention

Every scanner uses a single path prefix defined in `config.py`:

```python
HOST_ROOT = os.environ.get("HOST_ROOT", "/host")

PROC_PATH = f"{HOST_ROOT}/proc"    # /host/proc  →  host's process table
SYS_PATH  = f"{HOST_ROOT}/sys"     # /host/sys   →  kernel interfaces
ETC_PATH  = f"{HOST_ROOT}/etc"     # /host/etc   →  config files
VAR_PATH  = f"{HOST_ROOT}/var"     # /host/var   →  package databases, logs
HOME_PATH = f"{HOST_ROOT}/home"    # /host/home  →  user directories
```

Setting `HOST_ROOT=""` collapses every path back to the real system root, so the tool runs directly on a bare host without Docker. This makes local development painless — no Docker rebuild needed to test a scanner change.

### Stage 1: Scanner Execution Model

All nine scanners extend a single abstract base class:

```python
class BaseScanner(ABC):
    name: str

    def run(self) -> ModuleResult:
        start = time.time()
        try:
            raw_output, findings = self._scan()
            return ModuleResult(
                module_name=self.name,
                findings=findings,      # empty list before AI analysis
                raw_output=raw_output,  # everything collected, sent to AI
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            # Critical design: a failed scanner never aborts the run
            return ModuleResult(..., error=str(e))

    @abstractmethod
    def _scan(self) -> tuple[dict, list]:
        ...
```

The base class enforces two contracts:

1. **Error isolation.** A scanner that throws an exception returns an empty `ModuleResult` with `error` set. The rest of the assessment continues unaffected. If nmap fails because `NET_RAW` wasn't granted, the network module fails gracefully while the other eight modules complete normally. The final report marks the failed module clearly.

2. **Separation of collection and analysis.** Scanners return raw data in `raw_output` — they do not produce findings. Findings come from the AI in Stage 2. This means a scanner never needs to be updated when security baselines change; only the AI prompt needs tuning.

**Execution order matters.** The runner uses a `ThreadPoolExecutor` to run the eight fast scanners in parallel, while lynis (which takes 3–7 minutes) runs concurrently in a separate thread:

```
t=0s   ┌── network scanner    ──┐
       ├── services scanner   ──┤
       ├── os_hardening       ──┤  complete ~30–90s
       ├── users scanner      ──┤
       ├── processes scanner  ──┤
       ├── filesystem scanner ──┤
       ├── kernel scanner     ──┤
       └── packages scanner   ──┘
       ┌── lynis scanner ──────────────────────┐  complete ~3–7min
```

All results are collected before Stage 2 begins. If lynis is skipped via `--skip lynis`, the total scan time drops to under 2 minutes.

### Stage 2: The Data Flow into AI

Each scanner's `raw_output` dict is serialized to JSON and sent to Claude. The key design decision is what goes into `raw_output`. The scanner doesn't filter or pre-interpret — it collects everything that could be relevant and lets the AI decide what matters:

```
network scanner raw_output = {
    "hostname": "myserver",
    "interfaces": [...],          ← ip addr output
    "open_ports_ss": "...",       ← ss -tlnpu output
    "nmap_localhost": {"xml": "..."}, ← full nmap XML
    "nmap_primary": {"xml": "..."},
    "firewall_iptables": {...},   ← all three tables
    "firewall_ufw": {...},
    "ipv6_interfaces": "...",
    "routing_table": "...",
    "dns_config": "...",
    "hosts_file": "..."
}
```

This gets serialized, truncated to ~80,000 characters if needed, and wrapped in the analysis prompt. The AI returns structured JSON with findings, a risk score, and a module summary. Those are deserialized back into `Finding` dataclasses and attached to the `ModuleResult`.

The eight per-module AI calls run concurrently using `ThreadPoolExecutor` — they are independent API calls with no shared state. On a typical run this takes 60–120 seconds total.

### Stage 3: Synthesis and Report Assembly

After all modules have AI-annotated findings, a second AI call performs cross-module synthesis. This is where the tool's real value emerges: the synthesis prompt receives all findings from all modules at once and is explicitly asked to identify **attack chains** — sequences of findings that chain together into a real exploit path.

The synthesis produces:

- `overall_risk_rating` + `overall_risk_score` — a single risk verdict for the host
- `attack_chains` — 2–5 multi-step attack scenarios grounded in the actual findings
- `top_10_priorities` — finding IDs ranked by real exploitability on *this* host, not generic severity
- `executive_summary` — non-technical prose for a system owner
- `recommended_immediate_actions` — ordered action list

Everything assembles into a single `Report` dataclass which is then rendered to HTML and Markdown in parallel:

```python
@dataclass
class Report:
    hostname: str
    scan_timestamp: str
    os_info: dict
    module_results: list[ModuleResult]   # all 9 modules
    attack_chains: list[AttackChain]     # from synthesis
    top_priorities: list[str]            # finding IDs
    overall_risk_score: int              # 0–100
    overall_risk_rating: str             # CRITICAL/HIGH/MEDIUM/LOW
    executive_summary: str
    lynis_score: int | None
    recommended_actions: list[str]
    all_findings: list[Finding]          # flattened, populated post-init
```

### Component Map

```
assessment/
├── cli.py          Entry point. Parses args, orchestrates all three stages,
│                   prints the summary table to stdout.
│
├── config.py       Single source of truth for all paths (HOST_ROOT prefix),
│                   sysctl baselines, known-safe SUID list, dangerous packages.
│
├── models.py       Pure data: Finding, ModuleResult, AttackChain, Report.
│                   No business logic. Safe to import anywhere.
│
├── runner.py       Stage 1 orchestration. Validates mounts, collects host
│                   context (OS, kernel, hostname), runs scanners in parallel.
│
├── scanners/
│   ├── base.py     Abstract BaseScanner with error isolation + timing.
│   └── *.py        One file per module. Each implements _scan() only.
│                   No AI, no reporting, no cross-module awareness.
│
├── ai/
│   ├── client.py   Anthropic SDK wrapper. Handles retries, rate limits,
│   │               JSON parsing, and stripping markdown code fences.
│   ├── prompts.py  All prompt templates in one place. The single file
│   │               to edit when tuning AI analysis quality.
│   └── analyzer.py Stage 2 orchestration. Runs per-module analysis in
│                   parallel, then runs synthesis. Builds the Report.
│
└── reports/
    ├── html.py     Self-contained HTML renderer. Inline CSS + JS, no CDN.
    └── markdown.py Markdown renderer for archiving and plain-text sharing.
```

---

## The Nine Scanner Modules

Each scanner inherits from `BaseScanner`, which handles timing, error isolation, and result structure:

```python
class BaseScanner(ABC):
    name: str = "base"

    def run(self) -> ModuleResult:
        start = time.time()
        try:
            raw_output, findings = self._scan()
            return ModuleResult(
                module_name=self.name,
                findings=findings,
                raw_output=raw_output,
                ...
            )
        except Exception as e:
            # A failed scanner returns an empty result, not an exception
            # The rest of the assessment continues
            return ModuleResult(..., error=str(e))
```

This error isolation design is important: if lynis times out or nmap fails due to missing capabilities, the other seven modules still complete and get analyzed.

### Module 1: Network

Uses nmap for port scanning and service fingerprinting:

```bash
nmap -sS -sV --top-ports 1000 -T4 --open -oX - 127.0.0.1
nmap -sS -sV --top-ports 1000 -T4 --open -oX - <primary_ip>
```

Also reads iptables/nftables/ufw rules, checks IPv6 exposure, and uses `ss -tlnpu` to map listening processes to ports.

Key finding this catches: services binding to `0.0.0.0` (all interfaces) when they should bind only to localhost.

### Module 2: Services

Enumerates systemd units looking for:

- Failed services (which might indicate crashed security daemons)
- Services enabled at boot that shouldn't be there
- Services running as UID 0
- The docker socket: if `/var/run/docker.sock` is world-readable, any user can become root trivially

```python
def _check_docker_socket() -> dict:
    socket_path = "/var/run/docker.sock"
    if os.path.exists(socket_path):
        st = os.stat(socket_path)
        return {
            "exists": True,
            "mode": oct(st.st_mode),
            "world_readable": bool(st.st_mode & 0o006),  # Critical if True
        }
```

### Module 3: OS Hardening

Reads 25+ sysctl parameters directly from `/proc/sys/` and compares them against secure baselines. No `sysctl` command needed:

```python
SYSCTL_CHECKS = {
    "kernel.randomize_va_space": (2, "ASLR full randomization"),
    "kernel.dmesg_restrict":     (1, "Restrict dmesg to privileged users"),
    "kernel.kptr_restrict":      (2, "Hide kernel pointers"),
    "kernel.yama.ptrace_scope":  (1, "Restrict ptrace to parent processes"),
    "net.ipv4.tcp_syncookies":   (1, "SYN flood protection"),
    # ... 20 more
}
```

Also checks AppArmor/SELinux status, GRUB boot parameters (looking for `nokaslr`, missing `audit=1`), PAM configuration, and core dump settings.

### Module 4: Users

Parses `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, and SSH configuration to find:

- Accounts with UID 0 other than root
- System accounts (UID < 1000) with login shells
- `NOPASSWD` entries in sudoers
- Root's authorized SSH keys
- Legacy files (`.rhosts`, `.netrc`) in home directories
- SSH configuration weaknesses (PermitRootLogin, PasswordAuthentication, etc.)

### Module 5: Processes

Iterates `/proc/` with `--pid=host` giving access to all host PIDs. For each process it reads:

```python
# /proc/<pid>/status for UID, capabilities
# /proc/<pid>/cmdline for command line
# /proc/<pid>/exe for executable path
```

The capability decoding is particularly useful — it translates the hex bitmask from `/proc/<pid>/status` into human-readable capability names:

```python
cap_int = int("0000003fffffffff", 16)
caps = [CAP_NAMES[i] for i in range(41) if cap_int & (1 << i)]
# → ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', ..., 'CAP_SYS_ADMIN']
```

It also flags processes with deleted executables, shells running from `/tmp`, and command-line patterns suggesting reverse shells (`/dev/tcp`, `bash -i`, `0>&1`).

### Module 6: Filesystem

Walks the filesystem looking for SUID/SGID binaries, world-writable files in system directories, incorrect permissions on sensitive files, and missing sticky bits:

```python
sensitive_files = {
    "/etc/shadow":         0o640,  # max allowed mode
    "/etc/sudoers":        0o440,
    "/etc/sshd_config":    0o600,
    "/boot/grub/grub.cfg": 0o600,
}
```

Unknown SUID binaries — those not in the known-good baseline list — are flagged as high-priority findings.

### Module 7: Kernel

Reads CPU vulnerability status directly from `/sys/devices/system/cpu/vulnerabilities/`:

```
spectre_v1: Mitigation: usercopy/swapgs barriers and __user pointer sanitization
spectre_v2: Mitigation: Enhanced IBRS
meltdown:   Not affected
srbds:      Mitigation: Microcode
```

Each entry is parsed to determine whether mitigations are actually active or the CPU is exposed. Also checks kernel lockdown mode, whether kexec is disabled, and BPF access restrictions.

### Module 8: Packages

Uses the dpkg status database directly (no package manager command needed) and cross-references installed packages against the OSV.dev vulnerability database — no API key required:

```python
payload = {
    "package": {"name": "openssl", "ecosystem": "Debian"},
    "version": "3.0.2-0ubuntu1.12",
}
response = requests.post("https://api.osv.dev/v1/query", json=payload)
# Returns list of CVEs affecting this exact version
```

Also checks for dangerous legacy packages (`telnetd`, `rsh-server`, `nis`), package integrity via `dpkg --verify`, and whether automatic security updates are configured.

### Module 9: Lynis

Wraps the `lynis` command-line tool, running it against the mounted host filesystem:

```bash
lynis audit system --rootdir /host --no-colors --quiet \
    --report-file /tmp/lynis-report.dat
```

Then parses the structured report file to extract the hardening index score (0–100), warnings, suggestions, and per-category test results. The lynis score becomes a key metric in the final report.

---

## The AI Layer

This is where the tool differentiates from a plain script. There are two analysis passes.

### Pass 1: Per-Module Analysis

Each module's raw output is sent to Claude with this prompt structure:

```
Analyze the following {module_name} scan results from a Linux host
security assessment.

HOST CONTEXT:
OS: Ubuntu 24.04.2 LTS
Kernel: 6.8.0-49-generic
Hostname: myserver

RAW SCAN DATA:
{json_dump_of_scanner_output}

Identify security findings. For each finding output JSON:
{
  "id": "unique_snake_case_id",
  "title": "Short descriptive title",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "What the issue is and why it matters",
  "evidence": "Exact values/paths from the scan data",
  "remediation": "Specific command or config change to fix this"
}
```

Temperature is set to 0 for deterministic, consistent findings. The `evidence` field is crucial — it forces the model to ground every finding in actual data from the scan, preventing hallucinated findings.

These per-module calls run concurrently using `ThreadPoolExecutor` since they're independent API calls.

### Pass 2: Synthesis

After all modules are analyzed, a synthesis prompt combines all findings and asks for:

1. **Attack chains** — realistic multi-step scenarios specific to *this host's* actual findings
2. **Top 10 priorities** — ranked by exploitability and impact, not just generic severity
3. **Executive summary** — suitable for a system owner, not a security researcher
4. **Overall risk rating** — CRITICAL/HIGH/MEDIUM/LOW with justification

The attack chain analysis is the most valuable output. It identifies combinations like: *"The nginx service (finding: exposed\_http\_service) runs as root (finding: nginx\_root\_process), and there is a known CVE in the installed nginx version (finding: nginx\_cve\_2024\_xxxx). A remote attacker exploiting the CVE would gain immediate root access."*

---

## The Report

The HTML report is a single self-contained file — no CDN dependencies, no external JavaScript. Open it offline, share it via email, archive it. It includes:

- Color-coded severity dashboard
- Filterable findings table (click "Critical" to show only critical findings)
- Collapsible module sections with risk scores
- Attack chain cards
- Full lynis output in an appendix

The dark theme was a deliberate choice — security professionals spend a lot of time staring at these reports.

---

## What It Found on My Machine

Running it on my own development machine was humbling. Some highlights:

**High severity:** `kernel.dmesg_restrict = 0` — unprivileged users can read the kernel ring buffer, which leaks memory addresses that defeat ASLR.

**High severity:** Several services binding to `0.0.0.0` that should be localhost-only, including a development database I had forgotten was running.

**Medium severity:** Three SUID binaries outside the known-good baseline — two legitimate (installed by packages I forgot about), one I couldn't explain and removed immediately.

**Medium severity:** SSH `PasswordAuthentication yes` — I thought I had disabled this. I hadn't.

**Low severity:** 12 sysctl parameters not at their recommended values, mostly network hardening settings that Ubuntu doesn't enable by default.

The attack chain analysis correctly identified that two of the medium findings could combine into a privilege escalation path. That's the kind of correlation that takes a human analyst 20 minutes — the AI did it in 15 seconds.

---

## Security Considerations

A few important notes if you use this:

**The tool only reads, never writes.** Every host mount is `:ro`. The only write path is the `./output/` directory where reports are saved. Verify this yourself by checking the `docker run` command in `run.sh` before running.

**Keep reports private.** The HTML report contains detailed information about your system's configuration, installed packages, and vulnerabilities. Treat it like a password — don't commit it to a public repository, don't share it over unencrypted channels.

**Your scan data goes to Anthropic's API.** The raw scanner output is sent to Claude for analysis. Review Anthropic's data handling policies before running this in regulated environments. The `--no-ai` flag produces reports with no external data transmission.

**This is not a replacement for a professional penetration test.** It finds configuration weaknesses and known CVEs. It does not attempt exploitation, it doesn't cover application-layer vulnerabilities, and it won't catch a skilled attacker who has already compromised your system. It's a hardening tool, not a forensics tool.

---

## Extending the Tool

Adding a new scanner is straightforward. Create a class in `assessment/scanners/`:

```python
class MyScanner(BaseScanner):
    name = "my_module"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        # Collect data, store in result dict
        result["something"] = read_something()
        # Return raw data — AI will identify findings
        return result, []
```

Register it in `assessment/scanners/__init__.py`:

```python
ALL_SCANNERS = {
    ...
    "my_module": MyScanner,
}
```

That's it. The AI analysis, report generation, and CLI integration are automatic.

---

## What's Next

A few things I'm planning to add:

- **Differential reports** — compare two scans over time to see what changed
- **Remediation scripts** — auto-generated bash scripts to apply the recommended fixes (with dry-run mode)
- **CI/CD integration** — fail a pipeline if a scan finds CRITICAL severity issues
- **Rootkit detection** — integrate `rkhunter` or `chkrootkit` as an additional module
- **Container scanning** — extend the tool to also assess running Docker containers on the host

---

## Conclusion

Security tooling has historically required either significant expertise to interpret or significant budget to outsource. Large language models change that equation. Not because they replace security expertise — they don't — but because they can take the output of established tools and turn raw data into prioritized, actionable findings that a non-specialist can understand and act on.

The combination of Docker (clean, reproducible tooling), Python (rapid scanner development), and Claude (findings correlation and natural language output) produces something that would have taken a team weeks to build a few years ago.

The full source code is available on [GitHub](https://github.com/anpa1200/AuditAI). Run it on your machine. You might be surprised what you find.

---

*All assessments were performed on systems I own and operate. This tool is intended for authorized use on systems you have permission to assess.*

---

**Tags:** `security` `linux` `docker` `python` `ai` `devops` `cybersecurity` `claude`
