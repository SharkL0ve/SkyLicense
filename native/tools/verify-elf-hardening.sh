#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <libSkyLicense_64.so> [--require-integrity-manifest]" >&2
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
artifact=$1
require_manifest=${2:-}
[[ -f "$artifact" ]] || { echo "missing ELF artifact: $artifact" >&2; exit 1; }
[[ -z "$require_manifest" || "$require_manifest" == "--require-integrity-manifest" ]] || usage
command -v readelf >/dev/null 2>&1 || { echo "readelf is required" >&2; exit 1; }

header=$(readelf -hW "$artifact")
program_headers=$(readelf -lW "$artifact")
dynamic=$(readelf -dW "$artifact")

grep -Eq 'Class:[[:space:]]+ELF64' <<<"$header" || { echo "expected ELF64" >&2; exit 1; }
grep -Eq 'Machine:.*X86-64' <<<"$header" || { echo "expected x86-64 ELF" >&2; exit 1; }
grep -Eq 'Type:[[:space:]]+DYN \(Shared object file\)' <<<"$header" || { echo "expected shared object" >&2; exit 1; }
grep -q 'GNU_RELRO' <<<"$program_headers" || { echo "missing GNU_RELRO" >&2; exit 1; }
grep -Eq 'GNU_STACK.*RW[[:space:]]' <<<"$program_headers" || { echo "GNU_STACK is executable or malformed" >&2; exit 1; }
if grep -Eq 'LOAD.*RWE' <<<"$program_headers"; then
    echo "ELF contains an RWX load segment" >&2
    exit 1
fi
grep -q 'BIND_NOW' <<<"$dynamic" || { echo "missing BIND_NOW" >&2; exit 1; }

manifest_status=not-required
if [[ "$require_manifest" == "--require-integrity-manifest" ]]; then
    manifest="${artifact}.integrity"
    [[ -f "$manifest" ]] || { echo "missing integrity manifest: $manifest" >&2; exit 1; }
    [[ $(wc -c <"$manifest") -eq 160 ]] || { echo "integrity manifest must contain 160 bytes" >&2; exit 1; }
    magic=$(od -An -tx1 -N8 "$manifest" | tr -d '[:space:]')
    [[ "$magic" == "534b59494e543032" ]] || { echo "invalid integrity manifest magic" >&2; exit 1; }
    verifier=${SKYLICENSE_MANIFEST_VERIFIER:-target/release/verify_artifact}
    [[ -x "$verifier" ]] || { echo "full manifest verifier was not found or is not executable: $verifier" >&2; exit 1; }
    verification_output=$("$verifier" "$artifact")
    grep -qx 'verified=true' <<<"$verification_output" || { echo "artifact manifest verifier did not report verified=true" >&2; exit 1; }
    printf '%s\n' "$verification_output"
    manifest_status=cryptographically-valid
fi

echo "elf_hardening_verified=true"
echo "integrity_manifest=$manifest_status"
