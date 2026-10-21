#!/usr/bin/env python3
"""Compare a probe run against the vulnerable build with one against the fixed build.

    python scripts/negative_control.py vuln.json secure.json authzprobe/cases.yml

VAmPI gates three of its five authorization flaws behind `vulnerable=0`. That
makes it a free negative control: run the same cases against both builds and
the probe's output should track the guards in the source exactly.

Without this, "the probe found 8 violations" is unfalsifiable. A tool that
reports findings against every target it sees is indistinguishable from one
that works, until the day it matters. Three cases must go quiet on the fixed
build and two must not, and both directions are failures if they flip.

Exit codes:
    0  the probe tracked the guards exactly
    1  a case behaved differently from its declaration
    2  bad or missing inputs
"""

from __future__ import annotations

import json
import pathlib
import sys

import yaml


def load_case_ids(path: pathlib.Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {f["case_id"] for f in data.get("findings", [])}


def check(vuln: pathlib.Path, secure: pathlib.Path,
          cases: pathlib.Path) -> tuple[int, list[str]]:
    spec = yaml.safe_load(cases.read_text(encoding="utf-8")) or {}
    declared = {c["id"]: c.get("fixed_in_secure_mode") for c in (spec.get("cases") or [])}
    if not declared:
        return 2, [f"{cases} defines no cases"]
    undeclared = [cid for cid, v in declared.items() if v is None]
    if undeclared:
        return 2, [f"cases missing fixed_in_secure_mode: {sorted(undeclared)}"]

    firing_vuln = load_case_ids(vuln)
    firing_secure = load_case_ids(secure)

    rows, problems = [], []
    for cid, should_be_fixed in declared.items():
        in_vuln = cid in firing_vuln
        in_secure = cid in firing_secure

        if not in_vuln:
            problems.append(
                f"{cid}: no finding on the VULNERABLE build. The case no longer "
                f"reproduces, so the write-up is wrong."
            )
        elif should_be_fixed and in_secure:
            problems.append(
                f"{cid}: declared fixed in secure mode but still reported. Either "
                f"the probe has a false positive or the declaration is wrong."
            )
        elif not should_be_fixed and not in_secure:
            problems.append(
                f"{cid}: declared NOT fixed in secure mode but went quiet. The "
                f"probe is missing a flaw that is still present."
            )

        rows.append((cid, in_vuln, in_secure, should_be_fixed))

    width = max(len(c) for c in declared)
    lines = [f"{'case'.ljust(width)}  vuln=1  vuln=0  expected",
             f"{'-' * width}  ------  ------  --------"]
    for cid, a, b, fixed in rows:
        lines.append(
            f"{cid.ljust(width)}  {'FIRES' if a else '  -  ':<6}  "
            f"{'FIRES' if b else '  -  ':<6}  {'fixed' if fixed else 'still broken'}"
        )
    return (1 if problems else 0), lines + ([""] + problems if problems else [])


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    paths = [pathlib.Path(p) for p in sys.argv[1:4]]
    for p in paths:
        if not p.exists():
            print(f"::error::missing input: {p}", file=sys.stderr)
            return 2

    code, lines = check(*paths)
    for line in lines:
        print(line)
    print()
    if code == 0:
        print("negative control passed: the probe tracks the source guards exactly")
    else:
        print("::error::negative control failed, see above")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
