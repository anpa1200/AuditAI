import os
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

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
    ctx = {}

    # Hostname
    try:
        ctx["hostname"] = socket.gethostname()
    except Exception:
        ctx["hostname"] = "unknown"

    # OS info
    os_info = {}
    os_release = os.path.join(ETC_PATH, "os-release")
    if os.path.exists(os_release):
        with open(os_release) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    os_info[k] = v.strip('"')
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
    """Run the specified scanner modules in parallel (lynis runs first, sequentially)."""

    # Run lynis first since it's slow and other modules don't depend on it
    results = []
    parallel_modules = [m for m in modules if m != "lynis"]
    lynis_modules = [m for m in modules if m == "lynis"]

    # Start lynis in background thread while others run
    lynis_future = None
    executor = ThreadPoolExecutor(max_workers=6)

    futures = {}
    for module_name in parallel_modules:
        scanner_cls = ALL_SCANNERS.get(module_name)
        if not scanner_cls:
            logger.warning(f"Unknown scanner: {module_name}")
            continue
        scanner = scanner_cls()
        logger.info(f"Starting scanner: {module_name}")
        futures[executor.submit(scanner.run)] = module_name

    if lynis_modules:
        scanner_cls = ALL_SCANNERS["lynis"]
        scanner = scanner_cls()
        logger.info("Starting lynis scanner (may take several minutes)...")
        lynis_future = executor.submit(scanner.run)

    # Collect parallel results
    for future in as_completed(futures):
        module_name = futures[future]
        try:
            result = future.result()
            if verbose:
                logger.info(
                    f"Completed {module_name}: "
                    f"{len(result.findings)} raw findings, "
                    f"{result.duration_seconds:.1f}s"
                )
            results.append(result)
        except Exception as e:
            logger.error(f"Scanner {module_name} raised exception: {e}")

    # Wait for lynis
    if lynis_future:
        try:
            lynis_result = lynis_future.result()
            results.append(lynis_result)
        except Exception as e:
            logger.error(f"Lynis scanner failed: {e}")

    executor.shutdown(wait=False)

    # Sort by original module order
    module_order = {m: i for i, m in enumerate(modules)}
    results.sort(key=lambda r: module_order.get(r.module_name, 999))

    return results


def get_scan_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
