#!/usr/bin/env python3
import sys
import os
import logging
import click

from assessment.config import ANTHROPIC_API_KEY, DEFAULT_MODEL, OUTPUT_DIR
from assessment.scanners import ALL_SCANNERS
from assessment.runner import validate_host_mounts, collect_host_context, run_scanners, get_scan_timestamp
from assessment.ai.client import AIClient
from assessment.ai.analyzer import Analyzer, build_report
from assessment.reports.markdown import generate_markdown
from assessment.reports.html import generate_html
from assessment.models import Report
from assessment.config import SEVERITY_ORDER


@click.command()
@click.option("--modules", default="all",
              help="Comma-separated modules to run (default: all)")
@click.option("--skip", default="",
              help="Comma-separated modules to skip")
@click.option("--output-dir", default=OUTPUT_DIR,
              help="Output directory for reports")
@click.option("--format", "fmt", default="both",
              type=click.Choice(["html", "markdown", "both"]),
              help="Report format")
@click.option("--model", default=DEFAULT_MODEL,
              help="Claude model to use")
@click.option("--no-ai", is_flag=True, default=False,
              help="Skip AI analysis (scanners only)")
@click.option("--severity", default="LOW",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
              help="Minimum severity to include in report")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Verbose logging")
def main(modules, skip, output_dir, fmt, model, no_ai, severity, verbose):
    """Host Vulnerability Assessment Tool — Powered by Claude AI."""
    _setup_logging(verbose)

    click.echo(click.style("\n╔══════════════════════════════════════════╗", fg="cyan"))
    click.echo(click.style("║   HOST VULNERABILITY ASSESSMENT TOOL     ║", fg="cyan"))
    click.echo(click.style("╚══════════════════════════════════════════╝\n", fg="cyan"))

    # Validate API key if AI enabled
    api_key = os.environ.get("ANTHROPIC_API_KEY", ANTHROPIC_API_KEY)
    if not no_ai and not api_key:
        click.echo(click.style(
            "ERROR: ANTHROPIC_API_KEY not set. Use --no-ai to skip AI analysis.",
            fg="red"
        ))
        sys.exit(1)

    # Validate host mounts
    mount_warnings = validate_host_mounts()
    for warning in mount_warnings:
        click.echo(click.style(f"WARNING: {warning}", fg="yellow"))

    # Determine module list
    all_module_names = list(ALL_SCANNERS.keys())
    if modules == "all":
        selected = all_module_names
    else:
        selected = [m.strip() for m in modules.split(",") if m.strip()]
        invalid = [m for m in selected if m not in ALL_SCANNERS]
        if invalid:
            click.echo(click.style(f"ERROR: Unknown modules: {invalid}", fg="red"))
            click.echo(f"Available: {', '.join(all_module_names)}")
            sys.exit(1)

    skip_list = [m.strip() for m in skip.split(",") if m.strip()]
    selected = [m for m in selected if m not in skip_list]

    # Ensure output dir exists
    os.makedirs(output_dir, exist_ok=True)

    # Collect host context
    click.echo(click.style("► Collecting host context...", fg="blue"))
    host_context = collect_host_context()
    click.echo(
        f"  Hostname: {host_context['hostname']} | "
        f"OS: {host_context['os_name']} | "
        f"Kernel: {host_context['kernel_version']}"
    )

    scan_timestamp = get_scan_timestamp()

    # Run scanners
    click.echo(click.style(f"\n► Running {len(selected)} scanner modules...", fg="blue"))
    click.echo(f"  Modules: {', '.join(selected)}\n")

    with click.progressbar(length=len(selected), label="Scanning", show_pos=True) as bar:
        # We can't easily update progress during parallel execution,
        # so we just show completion
        module_results = run_scanners(selected, verbose=verbose)
        bar.update(len(selected))

    click.echo("")
    for mr in module_results:
        status = click.style("✓", fg="green") if not mr.error else click.style("✗", fg="red")
        click.echo(f"  {status} {mr.module_name:20s} {mr.duration_seconds:5.1f}s")

    # AI Analysis
    if not no_ai:
        click.echo(click.style("\n► Running AI analysis (Claude)...", fg="blue"))
        client = AIClient(model=model, api_key=api_key)
        analyzer = Analyzer(client=client, host_context=host_context)

        click.echo("  Analyzing modules...")
        module_results = analyzer.analyze_modules(module_results)

        click.echo("  Running synthesis...")
        synthesis = analyzer.synthesize(module_results)
    else:
        click.echo(click.style("\n► Skipping AI analysis (--no-ai)", fg="yellow"))
        synthesis = {
            "overall_risk_rating": "UNKNOWN",
            "overall_risk_score": 0,
            "executive_summary": "AI analysis was skipped. Review raw scanner output.",
            "attack_chains": [],
            "top_10_priorities": [],
            "recommended_immediate_actions": [],
        }

    # Build report
    report = build_report(module_results, synthesis, host_context, scan_timestamp)

    # Filter by minimum severity
    min_sev_order = SEVERITY_ORDER.get(severity, 4)
    for mr in report.module_results:
        mr.findings = [
            f for f in mr.findings
            if SEVERITY_ORDER.get(f.severity, 4) <= min_sev_order
        ]
    report.all_findings = []
    for mr in report.module_results:
        report.all_findings.extend(mr.findings)

    # Generate reports
    click.echo(click.style("\n► Generating reports...", fg="blue"))
    generated = []
    if fmt in ("html", "both"):
        path = generate_html(report, output_dir)
        generated.append(path)
        click.echo(f"  HTML: {path}")
    if fmt in ("markdown", "both"):
        path = generate_markdown(report, output_dir)
        generated.append(path)
        click.echo(f"  Markdown: {path}")

    # Summary
    counts = report.severity_counts()
    risk_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "yellow",
                  "LOW": "green", "UNKNOWN": "white"}.get(report.overall_risk_rating, "white")

    click.echo(click.style("\n╔══════════════════ SUMMARY ══════════════════╗", fg="cyan"))
    click.echo(f"  Overall Risk: " + click.style(f"{report.overall_risk_rating} ({report.overall_risk_score}/100)", fg=risk_color))
    if report.lynis_score is not None:
        click.echo(f"  Lynis Hardening Index: {report.lynis_score}/100")
    click.echo(f"  Findings:")
    click.echo(f"    {click.style(str(counts.get('CRITICAL', 0)), fg='red')} Critical  "
               f"{click.style(str(counts.get('HIGH', 0)), fg='yellow')} High  "
               f"{click.style(str(counts.get('MEDIUM', 0)), fg='yellow')} Medium  "
               f"{click.style(str(counts.get('LOW', 0)), fg='blue')} Low")
    if report.recommended_actions:
        click.echo(f"\n  Top Action: {report.recommended_actions[0]}")
    click.echo(click.style("╚══════════════════════════════════════════════╝\n", fg="cyan"))


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy libs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)


if __name__ == "__main__":
    main()
