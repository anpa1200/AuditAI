import os
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from assessment.config import PROC_PATH, SYS_PATH, ETC_PATH, HOST_ROOT
from assessment.models import ModuleResult
from assessment.scanners import ALL_SCANNERS

logger = logging.getLogger(__name__)


def validate_host_mounts() -> list[str]:
    """Return list of warnings about missing host mounts."""
    warnings = []
    if HOST_ROOT and HOST_ROOT != "/":
        required = [PROC_PATH, SYS_PATH, ETC_PATH]
        for path in required:
            if not os.path.isdir(path):
                warnings.append(f"Required host path not mounted: {path}")
    return warnings


def collect_host_context() -> dict:
    """Gather basic host information for AI prompts."""
    ctx: dict[str, Any] = {}

    # Hostname
    try:
        ctx["hostname"] = socket.gethostname()
    except Exception:
        ctx["hostname"] = "unknown"

    # OS info
    os_info = {}
    os_release = os.path.join(ETC_PATH, "os-release")
    try:
        with open(os_release) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    os_info[k] = v.strip('"')
    except OSError as e:
        logger.warning("Could not read host OS information: %s", e)
    ctx["os_info"] = os_info
    ctx["os_name"] = os_info.get("PRETTY_NAME", os_info.get("NAME", "Linux"))
    ctx["os_version"] = os_info.get("VERSION_ID", "")

    # Kernel version
    try:
        with open(os.path.join(PROC_PATH, "version")) as f:
            ctx["kernel_version"] = f.read().strip().split()[2]
    except Exception:
        ctx["kernel_version"] = "unknown"

    return ctx


def run_scanners(
    modules: list[str],
    verbose: bool = False,
) -> list[ModuleResult]:
    """Run the specified scanner modules in parallel and preserve failures."""

    results = []

    def run_module(module_name):
        scanner_cls = ALL_SCANNERS.get(module_name)
        if scanner_cls is None:
            raise ValueError(f"Unknown scanner: {module_name}")
        return scanner_cls().run()

    # Collect constructor and worker failures alike; always release the pool.
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(run_module, name): name for name in modules}
        for future in as_completed(futures):
            module_name = futures[future]
            try:
                result = future.result()
                if verbose:
                    logger.info(
                        "Completed %s: %s raw findings, %.1fs",
                        module_name, len(result.findings), result.duration_seconds,
                    )
                results.append(result)
            except Exception as e:
                logger.error("Scanner %s raised exception: %s", module_name, e)
                results.append(ModuleResult(module_name, [], {}, None, "Scanner failed", 0,
                                            str(e) or type(e).__name__))

    # Sort by original module order
    module_order = {m: i for i, m in enumerate(modules)}
    results.sort(key=lambda r: module_order.get(r.module_name, 999))

    return results


def get_scan_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
