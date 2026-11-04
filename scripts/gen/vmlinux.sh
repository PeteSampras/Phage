#!/usr/bin/env bash
# Generate the CO-RE kernel header from the running kernel's BTF.
# Linux only. Requires bpftool and a kernel with CONFIG_DEBUG_INFO_BTF=y.
# BPFTOOL overrides the bpftool binary (e.g. a distribution's versioned
# /usr/lib/linux-tools-<ver>/bpftool when the bpftool wrapper finds no tools
# package for the running kernel).
set -euo pipefail

OUT="bpf/include/vmlinux/vmlinux.h"
BPFTOOL="${BPFTOOL:-bpftool}"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
	echo "error: /sys/kernel/btf/vmlinux not found — kernel lacks BTF" >&2
	exit 1
fi

mkdir -p "$(dirname "$OUT")"
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "wrote $OUT"
