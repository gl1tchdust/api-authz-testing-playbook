"""Live reproduction test: do the documented cases still reproduce?

Skipped unless `AUTHZPROBE_TARGET` points at a running instance of the pinned
target. CI starts VAmPI and sets it; locally:

    export AUTHZPROBE_TARGET=http://127.0.0.1:5000
    python -m pytest authzprobe/ -q

The assertion is inverted from a normal test. The target is deliberately
vulnerable, so a case that stops producing a finding means something broke:
the probe, the case definition, or the pinned commit moved. A playbook whose
examples no longer reproduce is worse than no playbook, because a reader will
trust it.
"""

from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from authzprobe.probe import Probe, ProbeError

TARGET = os.environ.get("AUTHZPROBE_TARGET")
CASES = pathlib.Path(__file__).with_name("cases.yml")

pytestmark = pytest.mark.skipif(
    not TARGET, reason="set AUTHZPROBE_TARGET to a running instance of the target"
)


@pytest.fixture(scope="module")
def run():
    spec = yaml.safe_load(CASES.read_text(encoding="utf-8"))
    probe = Probe(spec, base_url=TARGET)
    try:
        findings = probe.run()
    except ProbeError as exc:
        pytest.fail(f"probe could not complete against {TARGET}: {exc}")
    return spec, probe, findings


def test_target_is_the_pinned_build(run):
    """A different commit invalidates every captured example in cases/."""
    spec, _, _ = run
    assert spec["target"]["commit"] == "f16052dce83f05847133ec98f01c5193a41de7d8"


def test_every_documented_case_still_reproduces(run):
    spec, _, findings = run
    found = {f.case_id for f in findings}
    expected = {c["id"] for c in spec["cases"]}
    missing = expected - found
    assert not missing, (
        f"these cases no longer reproduce against the target: {sorted(missing)}. "
        "Either the probe regressed or the target changed; do not ship the "
        "playbook until the write-ups match reality again."
    )


def test_findings_carry_the_mappings_a_report_needs(run):
    _, _, findings = run
    for f in findings:
        assert f.owasp.startswith("API"), f"{f.case_id} has no OWASP mapping"
        assert f.cwe.startswith("CWE-"), f"{f.case_id} has no CWE mapping"
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, f.severity
        assert f.detail, f"{f.case_id} has no detail to paste into a report"


def test_authorized_identities_are_not_reported(run):
    """The probe must not flag the identity that legitimately owns the object.

    This is the false-positive direction. A probe that flags everything is as
    useless as one that flags nothing, and is harder to notice.
    """
    spec, _, findings = run
    authorized = {
        c["id"]: set(c.get("authorized") or [])
        for c in spec["cases"] if c.get("type", "access") == "access"
    }
    for f in findings:
        for ident in authorized.get(f.case_id, set()):
            assert f"identity '{ident}'" not in f.detail, (
                f"{f.case_id}: flagged {ident!r}, which the case authorises"
            )


def test_anonymous_access_is_detected_somewhere(run):
    """At least one case must catch an unauthenticated 2xx.

    VAmPI serves /users/v1/_debug and /users/v1/{username} to anyone. If the
    probe stops noticing that, the header-stripping path is broken.
    """
    _, _, findings = run
    assert any("unauthenticated" in f.detail for f in findings)
