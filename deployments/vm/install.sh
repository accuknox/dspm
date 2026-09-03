#!/usr/bin/env bash
# Install the DSPM scanner VM deployment: configuration under /etc/dspm, systemd units,
# the retention rule and the sequential-run helper. Idempotent; re-run after changing instance files.
#
#   sudo ./install.sh                 # one timer per instance, all at 02:00 (+ up to 10 min jitter)
#   sudo ./install.sh --sequential    # one timer, instances run one after another
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_DIR=/etc/dspm
OUT_DIR=/var/lib/dspm/output
MODE=parallel

case "${1:-}" in
  "") ;;
  --sequential) MODE=sequential ;;
  -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
  echo "run as root: sudo $0 ${1:-}" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "warning: docker not found; the units expect /usr/bin/docker (edit systemd/*.service for podman)" >&2
fi

# ---- configuration -------------------------------------------------------------------------------
install -d -m 0750 "$CONF_DIR" "$CONF_DIR/instances" "$CONF_DIR/keys"
# The container runs as UID 1001, which has no passwd entry on the host: use chown with numeric ids
# (coreutils "install -o 1001" rejects an unknown numeric user on uutils-based systems such as Ubuntu 25.10+)
mkdir -p "$OUT_DIR" && chown 1001:0 "$OUT_DIR" && chmod 0750 "$OUT_DIR"

# Shared files: a real file in this folder wins; otherwise the example seeds the first install only.
# Env files are read by the Docker daemon (root): 0600. aws-config is read INSIDE the container by
# UID 1001 (group 0), so it must be group-readable: 0640.
for name in common.env aws-config image.env; do
  mode=0600; [[ $name == aws-config ]] && mode=0640
  if [[ -f "$SRC/$name" ]]; then
    install -m "$mode" -g 0 "$SRC/$name" "$CONF_DIR/$name"
  elif [[ ! -f "$CONF_DIR/$name" ]]; then
    install -m "$mode" -g 0 "$SRC/$name.example" "$CONF_DIR/$name"
  fi
done

# Instances: every real instances/*.env is (re)installed; the .example files never are.
shopt -s nullglob
for f in "$SRC"/instances/*.env; do
  install -m 0600 "$f" "$CONF_DIR/instances/$(basename "$f")"
done
# Key material and CA bundles, readable by the container's group 0
for f in "$SRC"/keys/*; do
  [[ "$(basename "$f")" == README.md ]] && continue
  install -m 0640 "$f" "$CONF_DIR/keys/$(basename "$f")"
done
shopt -u nullglob

# ---- units, helper, retention --------------------------------------------------------------------
install -m 0644 "$SRC"/systemd/dspm@.service "$SRC"/systemd/dspm@.timer \
                "$SRC"/systemd/dspm-all.service "$SRC"/systemd/dspm-all.timer /etc/systemd/system/
install -m 0755 "$SRC/bin/dspm-run-all" /usr/local/bin/dspm-run-all
install -m 0644 "$SRC/tmpfiles.d/dspm.conf" /etc/tmpfiles.d/dspm.conf
systemd-tmpfiles --create /etc/tmpfiles.d/dspm.conf
systemctl daemon-reload

# ---- timers ----------------------------------------------------------------------------------------
instances=()
for f in "$CONF_DIR"/instances/*.env; do
  [[ -f "$f" ]] || continue
  instances+=("$(basename "$f" .env)")
done
if [[ ${#instances[@]} -eq 0 ]]; then
  echo "no instance files in $CONF_DIR/instances: copy instances/*.env.example to <name>.env, edit, re-run" >&2
  exit 0
fi

if [[ $MODE == sequential ]]; then
  for i in "${instances[@]}"; do
    systemctl disable --now "dspm@$i.timer" 2>/dev/null || true
  done
  systemctl enable --now dspm-all.timer
else
  systemctl disable --now dspm-all.timer 2>/dev/null || true
  for i in "${instances[@]}"; do
    systemctl enable --now "dspm@$i.timer"
  done
fi

echo "installed ${#instances[@]} instance(s) in $MODE mode: ${instances[*]}"
echo "  run one now:  systemctl start dspm@${instances[0]}.service"
echo "  follow it:    journalctl -u dspm@${instances[0]}.service -f"
echo "  timers:       systemctl list-timers 'dspm*'"
