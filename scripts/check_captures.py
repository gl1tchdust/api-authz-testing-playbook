#!/usr/bin/env python3
"""Fail if the committed captures have drifted from the case definitions.

    python scripts/check_captures.py captures authzprobe/cases.yml findings.json

Every exchange quoted in `cases/` comes from a capture file. Adding a case and
forgetting to re-capture leaves a write-up with no evidence behind it, which is
the specific way a playbook rots: still readable, quietly wrong.

Exit codes:
    0  captures cover every defined case
    1  drift, or a missing input
"""

from __future__ import annotations

import json
import pathlib
import sys

import yaml


def check(captures_dir: pathlib.Path, cases_file: pathlib.Path,
          findings_file: pathlib.Path | None) -> tuple[int, list[str]]:
    messages: list[str] = []

    if not cases_file.exists():
        return 1, [f"case file not found: {cases_file}"]

    spec = yaml.safe_load(cases_file.read_text(encoding="utf-8")) or {}
    expected = {c["id"] for c in (spec.get("cases") or [])}
    if not expected:
        return 1, [f"{cases_file} defines no cases"]

    files = sorted(captures_dir.glob("*.md")) if captures_dir.is_dir() else []
    if not files:
        return 1, [f"no capture files in {captures_dir}"]

    captured = "\n".join(f.read_text(encoding="utf-8") for f in files)
    missing = sorted(cid for cid in expected if f"## {cid}" not in captured)
    if missing:
        messages.append(f"captures have no exchanges for: {missing}")
        messages.append("re-run: python -m authzprobe.probe --capture captures")

    if findings_file and findings_file.exists():
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
        reported = {f["case_id"] for f in findings.get("findings", [])}
        silent = sorted(expected - reported)
        if silent:
            messages.append(f"cases that produced no finding: {silent}")
        messages.append(
            f"{findings.get('violations', 0)} violations across {len(expected)} cases"
        )

    return (1 if missing else 0), messages


def main() -> int:
    args = sys.argv[1:]
    captures = pathlib.Path(args[0] if args else "captures")
    cases = pathlib.Path(args[1] if len(args) > 1 else "authzprobe/cases.yml")
    findings = pathlib.Path(args[2]) if len(args) > 2 else None

    code, messages = check(captures, cases, findings)
    for m in messages:
        print(f"::error::{m}" if code else m)
    if code == 0 and not messages:
        print("captures cover every defined case")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
