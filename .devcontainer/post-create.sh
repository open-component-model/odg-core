#!/usr/bin/env bash
set -euo pipefail

# Setup ODG
make setup

# Regenerate kubeconfig at each shell startup so changes to config-orig are reflected
ORIG='$HOME/.kube/config-orig'
DEST='$HOME/.kube/config'
BASHRC="$HOME/.bashrc"
MARKER='# odg-kubeconfig-refresh'
if ! grep -q "$MARKER" "$BASHRC" 2>/dev/null; then
    cat >> "$BASHRC" <<EOF

$MARKER
if [[ -f "$ORIG" ]]; then
    mkdir -p "\$(dirname "$DEST")"
    sed 's/127\\.0\\.0\\.1/host.docker.internal/g' "$ORIG" > "$DEST"
fi
EOF
    echo "Kubeconfig refresh hook added to $BASHRC"
fi