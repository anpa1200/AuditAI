# OWASP Project Application Draft

## Project

- **Proposed name:** OWASP AuditAI
- **Project type:** Tool
- **Current repository:** https://github.com/anpa1200/AuditAI
- **Project leader:** Andrey Pautov
- **GitHub username:** anpa1200
- **Leader email:** 1200km@gmail.com
- **License:** MIT
- **Current maturity:** Incubator candidate

## Summary

AuditAI is an open-source Linux host vulnerability assessment tool that runs
security scanner modules in Docker and produces a prioritized defensive report.
Optional AI analysis groups findings into plausible attack chains while keeping
the underlying scanner evidence available for analyst validation.

## OWASP Mission Alignment

AuditAI helps application owners, developers, platform engineers, and defenders
identify host-level weaknesses that can undermine deployed software. The project
focuses on repeatable defensive assessment, transparent evidence, remediation
prioritization, and safe operation in authorized environments.

## Current Capabilities

- Dockerized assessment workflow
- Nine security scanner modules
- Prioritized vulnerability findings
- Optional AI-assisted attack-chain synthesis
- Machine-readable and analyst-readable reporting
- Automated tests and GitHub Actions validation
- Debian packaging assets
- Public documentation and usage guidance

## Intended Users

- Application and platform security teams
- DevSecOps and infrastructure engineers
- Security consultants working under authorization
- Security educators and lab operators
- Defenders validating Linux host hardening

## Roadmap

1. Expand deterministic scanner coverage and normalize finding schemas.
2. Add reproducible test fixtures for every scanner module.
3. Improve remediation references and OWASP control mappings.
4. Add signed releases, SBOM generation, and supply-chain attestations.
5. Add plugin documentation and a stable integration API.
6. Build contributor onboarding and triage documentation.

## Governance And Safety

- The project is defensive and must only assess systems with authorization.
- Scanner evidence remains visible and must be validated before remediation.
- AI analysis is optional and is not treated as authoritative.
- Secrets and credentials must not be committed or included in reports.
- Contributions will use the OWASP-required contributor agreement or DCO.

## Existing Validation

- GitHub Actions CI: https://github.com/anpa1200/AuditAI/actions
- Source repository: https://github.com/anpa1200/AuditAI
- Published technical guide:
  https://medium.com/@1200km/building-a-dockerized-ai-powered-host-vulnerability-assessment-tool-cd6e2147ce59

## Transfer Decision Required

OWASP policy requires approved project source material to remain under the
Foundation's official source platform. Submit this application only after the
project leader explicitly approves transferring or migrating the project source
and adopting OWASP project branding and governance requirements.
