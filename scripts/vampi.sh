#!/usr/bin/env bash
# Fetch, run and seed the scan target.
#
#   ./scripts/vampi.sh fetch     # clone at the pinned commit, build its venv
#   ./scripts/vampi.sh run       # run in the FOREGROUND, blocks
#   ./scripts/vampi.sh wait      # block until it answers, then seed
#
#   VULNERABLE=0 ./scripts/vampi.sh run    # the fixed build, for the control
#
# Typical use, two terminals:
#
#   terminal 1:  ./scripts/vampi.sh fetch && ./scripts/vampi.sh run
#   terminal 2:  ./scripts/vampi.sh wait && python -m authzprobe.probe
#
# Or one, backgrounding it yourself:
#
#   ./scripts/vampi.sh fetch
#   ./scripts/vampi.sh run & ./scripts/vampi.sh wait
#
# `run` deliberately does not daemonise. An earlier version backgrounded the
# server itself and the child kept the script's stdout open, so piping the
# output anywhere hung forever waiting for an EOF. Detaching a child reliably
# across Linux and Git Bash on Windows is not worth the code it takes, and the
# caller already has `&`.
#
# Pinned to a commit. Every request and response in `cases/` was captured
# against this exact build, and `authzprobe/test_live.py` asserts the pin, so
# a moving target cannot silently invalidate the playbook.
#
# The target is fetched at run time, never vendored, so this repo carries no
# third-party source. VAmPI is MIT licensed.

set -euo pipefail

VAMPI_REPO="${VAMPI_REPO:-https://github.com/erev0s/VAmPI.git}"
VAMPI_SHA="${VAMPI_SHA:-f16052dce83f05847133ec98f01c5193a41de7d8}"
DEST="${DEST:-.target/vampi}"
PORT="${PORT:-5000}"
# VAmPI gates three of its five authorization flaws on this flag. Running the
# probe against both modes is the negative control: see README, "Negative
# control".
VULNERABLE="${VULNERABLE:-1}"
BASE="http://127.0.0.1:${PORT}"

# Windows virtualenvs put executables in Scripts/, not bin/.
venv_python() {
  if [ -x "$DEST/.venv/bin/python" ]; then echo "$DEST/.venv/bin/python"
  elif [ -x "$DEST/.venv/Scripts/python.exe" ]; then echo "$DEST/.venv/Scripts/python.exe"
  else return 1
  fi
}

cmd_fetch() {
  mkdir -p "$(dirname "$DEST")"
  if [ -d "$DEST/.git" ]; then
    echo "target already present at $DEST"
  else
    echo "cloning VAmPI into $DEST"
    git clone --quiet "$VAMPI_REPO" "$DEST"
  fi
  git -C "$DEST" fetch --quiet origin "$VAMPI_SHA" 2>/dev/null \
    || git -C "$DEST" fetch --quiet origin
  git -C "$DEST" checkout --quiet "$VAMPI_SHA"
  echo "target pinned at $(git -C "$DEST" rev-parse --short HEAD)"

  if ! venv_python >/dev/null 2>&1; then
    echo "building target virtualenv"
    python -m venv "$DEST/.venv"
    # VAmPI's own pins. They install cleanly on 3.12.
    "$(venv_python)" -m pip install --quiet --upgrade pip
    "$(venv_python)" -m pip install --quiet -r "$DEST/requirements.txt"
  fi
  echo "target ready to run: ./scripts/vampi.sh run"
}

cmd_run() {
  venv_python >/dev/null 2>&1 || { echo "run ./scripts/vampi.sh fetch first" >&2; exit 1; }
  # Absolute, because VAmPI reads its OpenAPI spec and sqlite file relative to
  # its own directory and therefore has to run from there.
  local rel py
  rel="$(venv_python)"
  py="$(cd "$(dirname "$rel")" && pwd)/$(basename "$rel")"
  echo "running target on $BASE (vulnerable=$VULNERABLE, ctrl-c to stop)"
  cd "$DEST"
  exec env vulnerable="$VULNERABLE" tokentimetolive=3600 "$py" app.py
}

cmd_wait() {
  echo -n "waiting for $BASE "
  for _ in $(seq 1 60); do
    if curl -sf "$BASE/" >/dev/null 2>&1; then
      echo "up"
      # Seed. Book titles are randomised per seed, which is why the probe
      # discovers them rather than hardcoding.
      curl -sf "$BASE/createdb" >/dev/null
      echo "seeded. users: name1/pass1  name2/pass2  admin/pass1"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo " timed out" >&2
  exit 1
}

case "${1:-}" in
  fetch) cmd_fetch ;;
  run)   cmd_run ;;
  wait)  cmd_wait ;;
  *) echo "usage: $0 {fetch|run|wait}" >&2; exit 1 ;;
esac
