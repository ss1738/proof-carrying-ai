#!/usr/bin/env bash
# Nightly differential fuzz on a Mac Mini.
#
# Syncs the fuzzer to a Mini, runs N iterations against the pre-built Rust
# backends + qedra there, writes a dated result log, and exits non-zero if any
# soundness divergence is found. Cron/launchd this, or run by hand.
#
#   FUZZ_N=2000 ./nightly.sh            # override iteration count
#   FUZZ_HOST=user@your-mini ./nightly.sh   # target a specific host
#
# For a true regression against code changes, re-sync + `cargo build --release`
# the rust/zkcore{,-gmp} crates on the Mini FIRST (that is your normal build flow),
# then run this — it fuzzes whatever binaries are currently built.
set -uo pipefail

HOST="${FUZZ_HOST:?set FUZZ_HOST=user@your-mini (or via the launchd plist EnvironmentVariables)}"
IDENT="${FUZZ_IDENT:-$HOME/.ssh/id_ed25519}"
N="${FUZZ_N:-2000}"
SSHOPTS=(-o IdentitiesOnly=yes -i "$IDENT" -o BatchMode=yes -o ConnectTimeout=10)

DIR="$(cd "$(dirname "$0")" && pwd)"
LOGDIR="$DIR/logs"; mkdir -p "$LOGDIR"
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
LOG="$LOGDIR/$STAMP.log"

echo "nightly differential fuzz -> $HOST  (N=$N)  $STAMP" | tee "$LOG"
scp "${SSHOPTS[@]}" "$DIR/differential_fuzz.py" "$HOST:/tmp/differential_fuzz.py" >/dev/null || { echo "scp failed" | tee -a "$LOG"; exit 2; }
ssh "${SSHOPTS[@]}" "$HOST" "cd /tmp && python3 -u differential_fuzz.py $N" 2>&1 | tee -a "$LOG"
rc="${PIPESTATUS[0]}"
echo "result: exit $rc" | tee -a "$LOG"
if [ "$rc" -ne 0 ]; then
  echo "DIVERGENCE — investigate $LOG" >&2
fi
exit "$rc"
