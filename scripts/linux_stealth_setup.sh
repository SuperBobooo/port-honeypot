#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
PORTS="${2:-}"

usage() {
  cat <<'EOF'
Linux stealth-mode RST blocking helper.

Usage:
  sudo scripts/linux_stealth_setup.sh setup 22,80,3389
  sudo scripts/linux_stealth_setup.sh cleanup 22,80,3389
  sudo scripts/linux_stealth_setup.sh status

What it does:
  - setup:   drops outbound TCP RST packets whose source port is in PORTS.
  - cleanup: removes those RST-drop rules.
  - status:  prints current porthoneypot rules.

The Rust client still needs to run as root or with CAP_NET_RAW to capture SYN
packets through a raw TCP socket.
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "error: this command must be run as root" >&2
    exit 1
  fi
}

normalize_ports() {
  if [[ -z "${PORTS}" ]]; then
    echo "error: ports are required, e.g. 22,80,3389" >&2
    exit 1
  fi
  echo "${PORTS}" | tr ',' ' ' | xargs -n1 | awk '
    /^[0-9]+$/ && $1 > 0 && $1 < 65536 { print $1; next }
    { printf("error: invalid port: %s\n", $1) > "/dev/stderr"; exit 1 }
  ' | sort -nu
}

iptables_setup() {
  local port
  while read -r port; do
    [[ -z "${port}" ]] && continue
    if iptables -C OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP 2>/dev/null; then
      echo "exists: iptables RST drop for source port ${port}"
    else
      iptables -A OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP
      echo "added: iptables RST drop for source port ${port}"
    fi
  done
}

iptables_cleanup() {
  local port
  while read -r port; do
    [[ -z "${port}" ]] && continue
    while iptables -C OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP 2>/dev/null; do
      iptables -D OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP
      echo "removed: iptables RST drop for source port ${port}"
    done
  done
}

nft_setup() {
  local port_set
  port_set="$(normalize_ports | paste -sd, -)"
  nft delete table inet porthoneypot >/dev/null 2>&1 || true
  nft add table inet porthoneypot
  nft add chain inet porthoneypot output '{ type filter hook output priority 0; policy accept; }'
  nft add rule inet porthoneypot output tcp sport "{ ${port_set} }" tcp flags rst drop comment '"porthoneypot-stealth-rst-drop"'
  echo "added: nftables RST drop for source ports ${port_set}"
}

nft_cleanup() {
  if nft list table inet porthoneypot >/dev/null 2>&1; then
    nft delete table inet porthoneypot
    echo "removed: nftables table inet porthoneypot"
  fi
}

case "${ACTION}" in
  setup)
    require_root
    if command -v iptables >/dev/null 2>&1; then
      normalize_ports | iptables_setup
    elif command -v nft >/dev/null 2>&1; then
      nft_setup
    else
      echo "error: neither iptables nor nft was found" >&2
      exit 1
    fi
    ;;
  cleanup)
    require_root
    if command -v iptables >/dev/null 2>&1; then
      normalize_ports | iptables_cleanup
    elif command -v nft >/dev/null 2>&1; then
      nft_cleanup
    else
      echo "error: neither iptables nor nft was found" >&2
      exit 1
    fi
    ;;
  status)
    if command -v iptables >/dev/null 2>&1; then
      iptables -S OUTPUT | grep -- '--tcp-flags RST RST' || true
    fi
    if command -v nft >/dev/null 2>&1; then
      nft list table inet porthoneypot 2>/dev/null || true
    fi
    ;;
  *)
    usage
    exit 1
    ;;
esac
