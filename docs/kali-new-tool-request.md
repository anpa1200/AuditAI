# Kali Linux New Tool Request: AuditAI

Submit under **New Tool Requests** at <https://bugs.kali.org/>.

## Summary

auditai - Linux host vulnerability assessment with optional AI synthesis

## Description

[Name] - AuditAI

[Version] - 1.0.0

[Homepage] - https://github.com/anpa1200/AuditAI

[Download] - https://github.com/anpa1200/AuditAI/releases/tag/v1.0.0

[Author] - Andrey Pautov

[Licence] - MIT

[Description] - AuditAI performs local Linux host vulnerability and hardening
assessments across network, services, users, processes, filesystem, kernel,
packages, and Lynis. The Kali package works without an API key using --no-ai;
Anthropic analysis remains optional.

[Dependencies] - Python 3, Click, Requests. Recommended: nmap, lynis, auditd,
iproute2, iptables, libcap2-bin, procps.

[Similar tools] - lynis, tiger, unix-privesc-check

[Activity] - Actively maintained with scanner and report-generation coverage.

[How to use] - `sudo auditai --no-ai --output-dir ./output`.

[Packaged] - Debian/Kali package metadata, autopkgtest, and a man page are
included upstream.

After Kali creates the issue, configure
[status notifications](kali-status-notifications.md).
