#!/usr/bin/env bash
# test-installer-verify.sh — CI test vector for the installer trust chain.
#
# Guards the verify mechanism install.sh relies on (ssh-keygen -Y verify over the
# signed aggregate manifest) and the trust-anchor constants. Uses a THROWAWAY test
# key — never the release key. The day someone touches the allowed_signers pin, the
# namespace, the rollback floor, or reintroduces a weaker fallback, this test says so.
#
# Runs offline (no network): generates a key, a known manifest and signature locally.
#   scripts/test-installer-verify.sh
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPTS_DIR/install.sh"
PASS=0; FAIL=0
ok()   { printf '  ok   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$1" >&2; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

[ -f "$INSTALL_SH" ] || { echo "FAIL: install.sh not found at $INSTALL_SH" >&2; exit 1; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "FAIL: ssh-keygen required" >&2; exit 1; }

# Pull the constants from install.sh so the test stays in sync with the installer.
NS="$(sed -n 's/^RVPN_SIGN_NAMESPACE="\([^"]*\)".*/\1/p' "$INSTALL_SH")"
FLOOR="$(sed -n 's/^RVPN_MIN_VERSION="\([^"]*\)".*/\1/p' "$INSTALL_SH")"
[ -n "$NS" ] || { echo "FAIL: could not read RVPN_SIGN_NAMESPACE from install.sh" >&2; exit 1; }
echo "namespace=$NS floor=$FLOOR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
KEY="$WORK/testkey"; MAN="$WORK/SHA256SUMS.txt"; SIG="$MAN.sig"; AS="$WORK/allowed_signers"

ssh-keygen -t ed25519 -f "$KEY" -N "" -C "$NS" -q
printf '%s %s\n' "$NS" "$(ssh-keygen -y -f "$KEY")" > "$AS"
# A second throwaway key, used by the e2e "signed by a different key" case below.
ssh-keygen -t ed25519 -f "$WORK/otherkey" -N "" -q

# Known manifest: version header (covered by the signature) + one artifact line.
ART_HASH="$(printf 'test-binary-bytes' | shasum -a 256 | awk '{print $1}')"
{
    printf '# rvpn-release signed manifest\n'
    printf '# version: %s\n' "$FLOOR"
    printf '%s  rvpn-macos-universal\n' "$ART_HASH"
} > "$MAN"

echo "── signature verify (the exact command install.sh uses) ──"
ssh-keygen -Y sign -f "$KEY" -n "$NS" "$MAN" 2>/dev/null
check "known key + manifest + signature verifies green" \
    'ssh-keygen -Y verify -f "$AS" -I "$NS" -n "$NS" -s "$SIG" < "$MAN" >/dev/null 2>&1'

cp "$MAN" "$WORK/good.man"
printf 'tampered\n' >> "$MAN"
check "tampered manifest is a HARD failure" \
    '! ssh-keygen -Y verify -f "$AS" -I "$NS" -n "$NS" -s "$SIG" < "$MAN" >/dev/null 2>&1'
cp "$WORK/good.man" "$MAN"

check "wrong namespace is a HARD failure" \
    '! ssh-keygen -Y verify -f "$AS" -I "$NS" -n "not-$NS" -s "$SIG" < "$MAN" >/dev/null 2>&1'
check "missing signature is a HARD failure" \
    '! ssh-keygen -Y verify -f "$AS" -I "$NS" -n "$NS" -s "$WORK/absent.sig" < "$MAN" >/dev/null 2>&1'

echo "── manifest parsing (version floor + artifact lookup) ──"
MVER="$(grep -m1 '^# version: ' "$MAN" | awk '{print $3}')"
check "version header parses to the floor value" '[ "$MVER" = "$FLOOR" ]'
LOOKUP="$(awk -v n="rvpn-macos-universal" '$2==n{print $1}' "$MAN")"
check "artifact line lookup returns the manifest hash" '[ "$LOOKUP" = "$ART_HASH" ]'
check "absent artifact lookup is empty (installer refuses)" \
    '[ -z "$(awk -v n="rvpn-not-present" '\''$2==n{print $1}'\'' "$MAN")" ]'

# version_lt: numeric dot compare (mirrors install.sh).
version_lt() {
    local a="$1" b="$2" i x y; local IFS=.
    set -- $a; local aa=("$@"); set -- $b; local bb=("$@")
    for i in 0 1 2; do x="${aa[$i]:-0}"; y="${bb[$i]:-0}"
        [ "$x" -lt "$y" ] && return 0; [ "$x" -gt "$y" ] && return 1; done
    return 1
}
echo "── rollback floor compare ──"
check "1.3.7 < 1.3.8 (older refused)" 'version_lt 1.3.7 1.3.8'
check "1.3.8 == 1.3.8 not below (accepted)" '! version_lt 1.3.8 1.3.8'
check "1.4.0 > 1.3.8 not below (accepted)" '! version_lt 1.4.0 1.3.8'
check "1.2.9 < 1.3.0 (older refused)" 'version_lt 1.2.9 1.3.0'

echo "── install.sh design invariants (no weaker fallback, anchors compiled in) ──"
check "compiled-in allowed_signers anchor present" 'grep -q "^RVPN_ALLOWED_SIGNERS=" "$INSTALL_SH"'
check "compiled-in rollback floor present" 'grep -q "^RVPN_MIN_VERSION=" "$INSTALL_SH"'
check "verify_manifest fetches the signed manifest" 'grep -q "SHA256SUMS.txt.sig" "$INSTALL_SH"'
check "verify_manifest uses ssh-keygen -Y verify" 'grep -q "ssh-keygen -Y verify" "$INSTALL_SH"'
# download_and_verify must NOT fetch a per-artifact .sha256 from the bucket anymore.
check "no per-artifact .sha256 fetch fallback (sha_url removed)" '! grep -q "sha_url=" "$INSTALL_SH"'
check "verify_manifest is wired before downloads" 'grep -q "^verify_manifest$" "$INSTALL_SH"'
# The shipped anchor LINE must carry the real release key, never the placeholder
# (install.sh also contains the placeholder string in its fail-closed detector —
# that one stays; only the RVPN_ALLOWED_SIGNERS assignment is pinned here).
check "real install.sh anchor line is not the placeholder" \
    '! grep "^RVPN_ALLOWED_SIGNERS=" "$INSTALL_SH" | grep -q "REPLACE_WITH_RELEASE_PUBKEY"'

echo "── verify_manifest end-to-end (install.sh's OWN code, local file:// origin) ──"
# Exercise the shipped verify_manifest, not a re-implementation (the version_lt
# mirror above can drift; these cases run the real function).
VFUNCS="$WORK/verify-funcs.sh"
{
    sed -n '/^info()/p;/^ok()/p;/^warn()/p;/^error()/p' "$INSTALL_SH"
    sed -n '/^version_lt()/,/^}/p' "$INSTALL_SH"
    sed -n '/^verify_manifest()/,/^}/p' "$INSTALL_SH"
} > "$VFUNCS"
grep -q 'verify_manifest()' "$VFUNCS" || { echo "FAIL: could not extract verify_manifest from install.sh" >&2; exit 1; }
GOOD_ANCHOR="$NS $(ssh-keygen -y -f "$KEY")"
# run_verify <manifest-version> <requested-version> [signing-key] [anchor] [tamper]
# Signs a manifest locally, lays it out as file://$WORK/e2e/<req>/, and runs the
# real verify_manifest in a subshell (its EXIT trap stays local).
run_verify() {
    local mver="$1" req="$2" skey="${3:-$KEY}" anchor="${4:-$GOOD_ANCHOR}" tamper="${5:-}"
    local dir="$WORK/e2e/$req"
    mkdir -p "$dir"
    {
        printf '# rvpn-release signed manifest\n'
        printf '# version: %s\n' "$mver"
        printf '%s  rvpn-macos-universal\n' "$ART_HASH"
    } > "$dir/SHA256SUMS.txt"
    rm -f "$dir/SHA256SUMS.txt.sig"  # cases reuse dirs; never let ssh-keygen prompt or leave a stale sig
    ssh-keygen -Y sign -f "$skey" -n "$NS" "$dir/SHA256SUMS.txt" 2>/dev/null
    [ -z "$tamper" ] || printf 'tampered\n' >> "$dir/SHA256SUMS.txt"
    (
        ASSETS_BASE="file://$WORK/e2e"
        VERSION="$req"
        DRY_RUN=false
        RVPN_MIN_VERSION="$FLOOR"
        RVPN_SIGN_NAMESPACE="$NS"
        RVPN_ALLOWED_SIGNERS="$anchor"
        MANIFEST_DIR=""; VERIFIED_MANIFEST=""
        CYAN=""; GREEN=""; YELLOW=""; RED=""; NC=""
        # shellcheck disable=SC1090
        source "$VFUNCS"
        verify_manifest
    ) >/dev/null 2>&1
}
check "e2e: valid sig + version == requested == floor -> accepted" \
    'run_verify "$FLOOR" "$FLOOR"'
check "e2e: SIGNED suffixed version above floor (1.3.9-rc1) -> hard fail" \
    '! run_verify "1.3.9-rc1" "1.3.9-rc1"'
check "e2e: SIGNED suffixed version below floor (1.3.7-rc1) -> hard fail" \
    '! run_verify "1.3.7-rc1" "1.3.7-rc1"'
check "e2e: signed manifest for a DIFFERENT release (1.9.9 vs $FLOOR) -> hard fail" \
    '! run_verify "1.9.9" "$FLOOR"'
check "e2e: strict below-floor version (1.3.7) -> hard fail" \
    '! run_verify "1.3.7" "1.3.7"'
check "e2e: tampered manifest after signing -> hard fail" \
    '! run_verify "$FLOOR" "$FLOOR" "$KEY" "$GOOD_ANCHOR" tamper'
check "e2e: placeholder anchor -> hard fail" \
    '! run_verify "$FLOOR" "$FLOOR" "$KEY" "$NS ssh-ed25519 AAAA_REPLACE_WITH_RELEASE_PUBKEY rvpn-release"'
check "e2e: signature by a different key -> hard fail" \
    '! run_verify "$FLOOR" "$FLOOR" "$WORK/otherkey"'

echo ""
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "installer-verify test vector: ALL GREEN"
