#!/usr/bin/env python3
"""Read a public Kali bug-tracker issue and emit normalized status fields."""

from __future__ import annotations

import argparse
import html
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def extract(page: str, field: str) -> str:
    pattern = rf'<td class="bug-{re.escape(field)}"[^>]*>(.*?)</td>'
    match = re.search(pattern, page, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    text = re.sub(r"<[^>]+>", " ", match.group(1))
    return " ".join(html.unescape(text).split())


def normalize(value: str) -> str:
    value = value.strip().lower()
    return re.sub(r"[^a-z0-9]+", "-", value).strip("-") or "unknown"


def outcome(status: str, resolution: str) -> str:
    status_value = normalize(status)
    resolution_value = normalize(resolution)
    if resolution_value in {"fixed", "implemented"}:
        return "accepted"
    if status_value == "closed" and resolution_value in {
        "wont-fix",
        "unable-to-reproduce",
        "not-fixable",
        "no-change-required",
        "duplicate",
        "suspended",
        "won-t-fix",
    }:
        return "rejected"
    return "pending"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue_id")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    url = f"https://bugs.kali.org/view.php?id={args.issue_id}"
    request = Request(url, headers={"User-Agent": "1200km-kali-status-monitor/1.0"})
    try:
        with urlopen(request, timeout=30) as response:
            page = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"Unable to read {url}: {exc}", file=sys.stderr)
        return 1

    values = {
        "issue_id": args.issue_id,
        "url": url,
        "status": extract(page, "status"),
        "resolution": extract(page, "resolution") or "open",
        "assigned_to": extract(page, "assigned-to") or "unassigned",
        "last_modified": extract(page, "last-modified") or "unknown",
        "summary": extract(page, "summary") or f"Kali issue {args.issue_id}",
    }
    if not values["status"]:
        print(f"Kali issue {args.issue_id} was not found or is not public.", file=sys.stderr)
        return 1

    values["status_key"] = normalize(f'{values["status"]}-{values["resolution"]}')
    values["outcome"] = outcome(values["status"], values["resolution"])

    lines = [f"{key}={value}" for key, value in values.items()]
    print("\n".join(lines))
    if args.output:
        with open(args.output, "a", encoding="utf-8") as output:
            output.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
