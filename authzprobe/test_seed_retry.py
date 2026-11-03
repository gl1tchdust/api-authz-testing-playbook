"""Regression test: seeding survives the target's self-colliding seed data.

VAmPI gives each of its three seed users one book titled
"bookTitle<randrange(100)>" and declares books.book_title UNIQUE, so three
draws from 100 collide about 3% of the time and /createdb answers 500. On
2026-11-03 that turned the weekly scheduled build red against code nobody had
touched. Measured over 300 consecutive seeds before the fix: 11 failures.

`scripts/vampi.sh seed` now retries, which is safe because /createdb calls
drop_all() before seeding, so a retry re-rolls from an empty database rather
than writing on top of a partial one.

These tests drive the script against a stub that fails on demand, so the
collision is deterministic here instead of a 3% chance. No VAmPI, no network.
"""

from __future__ import annotations

import http.server
import os
import pathlib
import shutil
import subprocess
import threading

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "vampi.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("curl") is None,
    reason="needs bash and curl to drive the shell script",
)


class _Target(http.server.BaseHTTPRequestHandler):
    """Answers /createdb with 500 for the first `fail_times` requests."""

    fail_times = 0
    seen = 0

    def do_GET(self):  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        if self.path.rstrip("/") in ("", "/"):
            self.send_response(200)
            self.end_headers()
            return
        if self.path.startswith("/createdb"):
            type(self).seen += 1
            if type(self).seen <= type(self).fail_times:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"UNIQUE constraint failed: books.book_title")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{ "message": "Database populated." }')
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture
def target():
    """A stub target. Set `.fail_times` before calling the script."""
    _Target.seen = 0
    _Target.fail_times = 0
    server = http.server.HTTPServer(("127.0.0.1", 0), _Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def run_seed(port, attempts=5):
    env = dict(os.environ, PORT=str(port), SEED_ATTEMPTS=str(attempts))
    return subprocess.run(
        ["bash", str(SCRIPT), "seed"],
        env=env, capture_output=True, text=True, timeout=60,
    )


def test_a_clean_seed_needs_one_attempt(target):
    done = run_seed(target)
    assert done.returncode == 0
    assert _Target.seen == 1
    assert "re-rolling" not in done.stderr


def test_a_collision_is_retried_rather_than_failing_the_build(target):
    _Target.fail_times = 1
    done = run_seed(target)
    assert done.returncode == 0, done.stderr
    assert _Target.seen == 2, "should have re-rolled exactly once"
    assert "seeded." in done.stdout


def test_four_collisions_still_recover_within_five_attempts(target):
    _Target.fail_times = 4
    done = run_seed(target)
    assert done.returncode == 0, done.stderr
    assert _Target.seen == 5


def test_a_target_that_never_seeds_fails_loudly(target):
    """Retrying must not mask a target that is genuinely broken."""
    _Target.fail_times = 99
    done = run_seed(target)
    assert done.returncode != 0
    assert _Target.seen == 5, "must stop at SEED_ATTEMPTS, not retry forever"
    assert "not the known collision" in done.stderr
