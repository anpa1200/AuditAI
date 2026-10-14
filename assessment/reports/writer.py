"""Write sensitive reports privately without following existing file symlinks."""

import os
import re
import tempfile


def write_report(output_dir: str, timestamp: str, extension: str, content: str) -> str:
    # Keep caller-supplied timestamps within a single output filename.
    timestamp = re.sub(r"[^A-Za-z0-9_.+-]", "_", str(timestamp).replace(":", "-"))
    path = os.path.join(output_dir, f"report_{timestamp}.{extension}")
    descriptor, temporary = tempfile.mkstemp(prefix=".auditai-report-", dir=output_dir)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        # Replace the directory entry itself, including an existing symlink.
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path
