# Kali Linux New Tool Request: AuditAI

Submit under **New Tool Requests** at <https://bugs.kali.org/>.

Do not submit this through `kali-meta`; Kali maintainers directed new tool
requests to the bug tracker workflow documented at:
<https://www.kali.org/docs/tools/submitting-tools/>.

## Summary

auditai - Linux host vulnerability assessment with optional AI synthesis

## Description

[Name] - AuditAI

[Version] - 1.0.0

Use the tagged release, not a moving branch:
<https://github.com/anpa1200/AuditAI/releases/tag/v1.0.0>

[Homepage] - <https://github.com/anpa1200/AuditAI>

[Download] -

- Release: <https://github.com/anpa1200/AuditAI/releases/tag/v1.0.0>
- PyPI: <https://pypi.org/project/1200km-auditai/>

[Author] - Andrey Pautov

[Licence] - MIT

[Description] - AuditAI performs Linux host vulnerability and hardening
assessment across process, network, service, filesystem, package, kernel, user,
and security-tool signals. The packaged CLI can run locally on Kali/Linux with
`--no-ai`, producing reports without any API key. Optional Anthropic-backed
analysis adds prioritization, cross-module synthesis, and attack-chain context.
The Docker workflow is available upstream, but the Kali-relevant path is the
local CLI.

[Dependencies] -

Runtime Python dependencies:

- Python >= 3.10
- click >= 8.1
- requests >= 2.31

Optional AI dependency:

- anthropic >= 0.40

Recommended external tools for richer host assessment:

- nmap
- lynis
- auditd
- iproute2
- iptables/nftables tools
- libcap2-bin
- procps

[Similar tools] - lynis, tiger, unix-privesc-check, debsecan, chkrootkit,
rkhunter. AuditAI is focused on aggregating host evidence into a single
assessment report with optional AI synthesis.

[Activity] - Active. Public release v1.0.0 was published on 2026-06-14. The
project includes PyPI packaging, GitHub release artifacts, CI, tests,
Debian/Kali packaging metadata, a man page, and autopkgtest metadata.

[How to install] -

From the tagged PyPI release:

```bash
pipx install 1200km-auditai
auditai --help
```

Or from the release source archive:

```bash
wget https://github.com/anpa1200/AuditAI/archive/refs/tags/v1.0.0.tar.gz
tar -xf v1.0.0.tar.gz
cd AuditAI-1.0.0
python3 -m venv .venv
. .venv/bin/activate
pip install .
auditai --help
```

[How to use] -

```bash
sudo auditai --no-ai --output-dir ./output
auditai --help
```

Optional AI-backed synthesis requires `ANTHROPIC_API_KEY`; the `--no-ai` mode is
intended for normal local CLI operation without external API use.

[Packaged] - Not currently packaged in Debian or Kali. Upstream includes
Debian/Kali packaging metadata under `debian/`, a man page, and autopkgtest
metadata to make Kali review easier.

