#!/usr/bin/env bash
# Pinned in-house release build (FORK.md "Building a release").
#
# Builds phaged, phage and phage-jail as static binaries (CGO_ENABLED=0) with
# -trimpath and the commit embedded by -buildvcs, with exactly the Go version
# go.mod names (GOTOOLCHAIN=local: the toolchain is never downloaded), compiles
# the eBPF objects against a vmlinux.h generated from this host's kernel BTF,
# and writes SHA256SUMS. Linux only.
#
#   scripts/build/release.sh            # or: make release
#
# Environment:
#   OUT          output directory (default dist/release/<version>)
#   BPFTOOL      bpftool binary for vmlinux.h (default bpftool)
#   GOTOOLCHAIN  go<go.mod's version> to fetch exactly that toolchain; any
#                other value is replaced by local
#   ALLOW_DIRTY  1 builds an uncommitted tree (marked -dirty and
#                vcs.modified=true; never ship one)
set -euo pipefail

cd "$(dirname "$0")/../.."
die() { echo "release: $*" >&2; exit 1; }

for tool in go git clang sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || die "missing $tool"
done
[[ "$(uname -s)" == Linux ]] || die "the eBPF objects build on Linux only"

# --- the pinned Go version -------------------------------------------------
# A `toolchain` line, when present, is the exact version; otherwise the `go`
# line is. The toolchain that builds must be exactly that version. By default
# only the local one is used (GOTOOLCHAIN=local: go never fetches another
# behind our back). GOTOOLCHAIN=go<that version> is also accepted: go then
# fetches that exact toolchain, verified against the Go checksum database.
want=$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2; exit }' go.mod)
[[ -n "$want" ]] || want=$(awk '$1 == "go" { print $2; exit }' go.mod)
[[ -n "$want" ]] || die "go.mod names no go version"
if [[ "${GOTOOLCHAIN:-}" != "go$want" ]]; then
	export GOTOOLCHAIN=local
fi
have=$(go env GOVERSION)
[[ "$have" == "go$want" ]] || die "go.mod pins go$want but the local toolchain is $have; install go$want, or run with GOTOOLCHAIN=go$want"

# --- the source --------------------------------------------------------------
commit=$(git rev-parse --verify HEAD)
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
	[[ "${ALLOW_DIRTY:-}" == 1 ]] || die "the tree has uncommitted changes; commit them, or ALLOW_DIRTY=1 for a throwaway build"
	echo "release: WARNING building a dirty tree (not for deployment)" >&2
fi
version=$(git describe --tags --always --dirty)
out=${OUT:-dist/release/$version}
rm -rf "$out"
mkdir -p "$out/bpf"

# --- eBPF objects ------------------------------------------------------------
./scripts/gen/vmlinux.sh
rm -f bpf/build/*.bpf.o
make --no-print-directory bpf
cp bpf/build/*.bpf.o "$out/bpf/"

# --- Go binaries -------------------------------------------------------------
export CGO_ENABLED=0
export GOFLAGS=
for cmd in phaged phage phage-jail; do
	go build -trimpath -buildvcs=true -ldflags "-buildid= -X main.version=$version" \
		-o "$out/$cmd" "./cmd/$cmd"
done

# Prove what was embedded rather than assume it.
info=$(go version -m "$out/phaged")
grep -q "vcs.revision=$commit" <<<"$info" || die "phaged does not embed vcs.revision=$commit"
grep -q "CGO_ENABLED=0" <<<"$info" || die "phaged was not built with CGO_ENABLED=0"
grep -q -- "-trimpath=true" <<<"$info" || die "phaged was not built with -trimpath"
if [[ "${ALLOW_DIRTY:-}" != 1 ]]; then
	grep -q "vcs.modified=false" <<<"$info" || die "phaged embeds vcs.modified=true"
fi

# --- the rest of the install set and provenance ------------------------------
cp deploy/phage.service configs/phage.example.yaml LICENSE "$out/"
{
	echo "version $version"
	echo "commit $commit"
	echo "go $(go env GOVERSION) GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 -trimpath -buildvcs=true"
	echo "clang $(clang --version | head -n1)"
	echo "vmlinux.h sha256 $(sha256sum bpf/include/vmlinux/vmlinux.h | cut -d' ' -f1) from kernel $(uname -r)"
} >"$out/BUILDINFO"

(
	cd "$out"
	sha256sum phaged phage phage-jail bpf/*.bpf.o phage.service phage.example.yaml LICENSE BUILDINFO >SHA256SUMS
)
echo "release: $out (commit $commit)"
echo "release: verify with: (cd $out && sha256sum -c SHA256SUMS)"
