#!/usr/bin/env bash
# Loom VM apply helper.
# Invoked only by Loom after Origin SHA evidence (POST /v1/releases/loom/{oid}/deploy).
# CI must not call this: it builds release binaries and restarts the loom unit.
#
# Idempotent: a second apply of the same SHA is a no-op when /var/lib/loom/applied-oid
# already records that object id.
set -euo pipefail

OID="${1:?usage: apply.sh <git-oid>}"
ROOT="${LOOM_APPLY_ROOT:-/opt/loom}"
STATE="${LOOM_APPLY_STATE:-/var/lib/loom/applied-oid}"
PREFIX="${LOOM_INSTALL_PREFIX:-/usr/local}"
HEALTH_URL="${LOOM_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
GRID_CLI="${LOOM_GRID_CLI_PATH:-${PREFIX}/libexec/grid/loom}"

# Invoked from sandboxed loom.service, hop to grid-01 and incus-exec back
# so `systemctl restart loom` does not kill this process with the unit.
if [[ -z "${LOOM_APPLY_INPLACE:-}" && -n "${ORIGIN_DEPLOY_SSH_HOST:-}" && -n "${ORIGIN_DEPLOY_SSH_KEY:-}" ]]; then
  user="${ORIGIN_DEPLOY_SSH_USER:-root}"
  exec ssh -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=accept-new \
    -i "${ORIGIN_DEPLOY_SSH_KEY}" \
    "${user}@${ORIGIN_DEPLOY_SSH_HOST}" -- /usr/local/sbin/loom-vm-apply "$OID"
fi

# Match the loom.service toolchain layout on the VM.
export CARGO_HOME="${CARGO_HOME:-/var/lib/loom/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/loom/rustup}"
export PATH="${CARGO_HOME}/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"

mkdir -p "$(dirname "$STATE")"
if [[ -f "$STATE" && "$(cat "$STATE")" == "$OID" ]]; then
  echo "loom apply: $OID already deployed"
  exit 0
fi

cd "$ROOT"
export GIT_TERMINAL_PROMPT=0
git fetch --force origin "$OID"
git checkout --detach "$OID"
# Build artifacts live outside the checkout so target/ cannot fill the small
# volume that holds /opt. CARGO_HOME already lives under /var/lib/loom.
export CARGO_TARGET_DIR="${LOOM_CARGO_TARGET_DIR:-/var/lib/loom/target}"
mkdir -p "$CARGO_TARGET_DIR"
cargo build --release -p loom -p loom-cli
install -m 0755 "$CARGO_TARGET_DIR/release/loom" "$PREFIX/bin/loom"
install -m 0755 "$CARGO_TARGET_DIR/release/loom-git-hook" "$PREFIX/bin/loom-git-hook"
# The host's `loom` name belongs to the server. Export the client under a
# Grid-only path; Grid installs it into guests as `loom` with a `loom-cli`
# compatibility alias.
install -d -m 0755 "$(dirname "$GRID_CLI")"
install -m 0755 "$CARGO_TARGET_DIR/release/loom-cli" "$GRID_CLI"
# One-time reclaim of the in-tree target dir from applies before the
# CARGO_TARGET_DIR isolation above.
rm -rf "$ROOT/target"
systemctl restart loom
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 --max-time 5 "$HEALTH_URL" >/dev/null
printf '%s\n' "$OID" >"$STATE"
echo "loom apply: deployed $OID"
