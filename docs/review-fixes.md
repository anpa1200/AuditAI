# AuditAI repository review and verified fixes

Review baseline: `8df39f38056c6f1b2db5fb1d4ce962367a400a04`.
Scope: all assessment modules, CLI/configuration, model/report consumers, shell
launcher, Docker configuration, packaging, workflow/helper scripts, tests, and
documentation. Verification uses synthetic files and mocked commands/services;
it does not assess a real host or invoke Anthropic, OSV, SMTP, or nmap.

Severity below describes the potential consequence, not proof of exploitation.

| Severity | Verified issue | Correction / regression evidence |
|---|---|---|
| High | Exhausted AI retries and module exceptions could appear as zero-risk success | Explicit module/report errors, unavailable scores, retained scanner evidence; `test_ai_errors.py` |
| High | Invalid or incomplete AI JSON could default to a clean assessment or crash reporting | Validate shapes, scores, severity, findings, chains, and references; `test_ai_validation.py` |
| High | Unescaped report strings could inject executable HTML | Escape HTML and neutralize Markdown markup from evidence/model output; `test_reports_review.py` |
| High | Predictable report names followed existing symlinks; sensitive reports inherited public file modes | Private temporary file and atomic replacement, without changing directory permissions; `test_reports_review.py` |
| High | Remote Kali tracker fields were interpolated into workflow shell source | Pass fields as environment data, write comment bodies from a quoted Python heredoc; `test_packaging_review.py` |
| Medium | Worker/constructor failures disappeared from structured results | Retain one failed result per requested module and release the executor; `test_runner_errors.py`, `test_scanners_review.py` |
| Medium | Shared Lynis report could reuse stale results; missing/nonzero/no-report runs looked successful | Private per-run report directory and explicit failures; `test_scanners_review.py` |
| Medium | Preprocessing dropped CPU vulnerability objects, actual kernel field names, collection failures, group membership, and service identities | Retain actual scanner schemas and unknown/error observations; `test_preprocessor_review.py` |
| Medium | CPU partial mitigation and lockdown `[none]` were misclassified | Evaluate the active lockdown mode, preserve unknown/unreadable status; `test_scanners_review.py` |
| Medium | Numeric permission comparisons missed excessive bits and public SSH keys were treated like private keys | Compare permission masks and separate public-key baseline; `test_scanners_review.py` |
| Medium | Mounted-host scans could substitute container paths, sysctl, package verification/updates, or service state | Honor host roots, use host package roots, report unavailable probes explicitly; `test_scanners_review.py` |
| Medium | Package queries used wrong OSV ecosystems/binary names and hid lookup failures | Distribution-release/source-aware queries and explicit coverage/errors; `test_scanners_review.py` |
| Medium | OS EOL used a frozen date and kernel series implied unsupported status without evidence | Use current date for known OS EOL dates; kernel support remains unknown without distribution evidence; `test_scanners_review.py` |
| Medium | `--no-ai` reports omitted collected raw evidence | Include complete escaped raw JSON in both formats; `test_reports_review.py` |
| Medium | Empty/duplicate/unknown module selections and AI initialization failure were mishandled | Validate selections before scanning, deduplicate, save evidence on initialization failure; `test_cli_validation.py` |
| Medium | Finding IDs could collide across AI-analyzed modules | Prefix IDs with the module name and reject unknown synthesis references; `test_ai_validation.py` |
| Low | Nmap XML/service parsing and headerless `ss` parsing lost observations | Structured XML parsing, preserved fallback evidence and spaced process fields; `test_preprocessor_review.py` |
| Low | `run.sh --no-ai` still prompted for an API key | Respect explicit disablement and preserve argument boundaries; `test_packaging_review.py` |
| Medium | Installed Anthropic SDK no longer accepted the explicit `temperature` keyword | Use the supported request signature; offline SDK signature regression in `test_ai_errors.py` |
| Low | Build metadata declared a setuptools version too old for the SPDX license syntax; sdist lacked helper inputs | Raise build floor and add source manifest; distribution build and `test_packaging_review.py` |
| Low | Feature branch pushes had no CI coverage | Enable branch CI with Python 3.10/3.12/3.13 tests, correctness lint, distribution builds, and existing Debian build |

## Resulting contract

`ModuleResult.error` and aggregate `Report.error` make incomplete assessments
explicit. Incomplete overall risk is `UNKNOWN` with score `None`. Reports retain
available evidence; the CLI writes reports and exits 1. Permanent AI authentication
or billing failures retain their immediate exit-1 behavior. Malformed JSON, missing
text, and token truncation get at most four client attempts, without hidden SDK
retries or a final unnecessary delay. Semantic response errors are reported as
failed analysis. AI finding IDs use `module:id`.

The raw `packages.cve_findings` value is now an object containing lookup status,
ecosystem, counts, limits, errors, and a `findings` list. A failed/unsupported
lookup is distinguishable from a completed lookup with no matched advisories.
Debian and Ubuntu ecosystem names follow the
[OSV schema](https://ossf.github.io/osv-schema/#affectedpackageecosystem-field).

## Verification and limits

The local full suite, CI correctness lint (`E4,E7,E9,F`), Python compilation and
3.10 syntax checks, shell syntax, source/wheel builds, extracted-source tests,
and wheel CLI smoke checks are run before push. GitHub CI is checked separately;
its run status belongs in the completion report, not an assertion in this file.
Mypy checks (`--ignore-missing-imports assessment`) also run locally and in the Python CI matrix; heterogeneous raw dictionaries have explicit annotations. Broader inherited Ruff
style/security diagnostics are distinct from the selected CI correctness checks.

Local Debian package building requires `dh-python`, `pybuild-plugin-pyproject`,
`python3-all`, and `python3-pytest`, which are missing in the review environment.
The configured CI Debian job is the package validation path. Docker runtime,
real host observations, live service behavior, and real paid model quality remain
unverified. Optional probes remain best effort; an empty observation alone is
not assurance of safety. OSV coverage is intentionally limited to 30 selected
high-risk packages and up to three advisories per package; other distributions
and Ubuntu Pro/ESM coverage are not claimed.

`--no-ai` disables Claude only; the packages scanner still queries OSV. Shared
host namespaces and capabilities grant sensitive host access despite read-only
mounts. AI output requires human validation, and untrusted host evidence may
influence model conclusions. No remediation commands are executed automatically.
