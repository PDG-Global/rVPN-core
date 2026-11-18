#!/bin/bash
# R-VPN Universal Installer
#
# Usage:
#   curl -fsSL https://assets.rvpn.org/install.sh | bash
#   # Or:
#   bash install.sh [OPTIONS]
#
# Options:
#   --version VERSION   Install specific version (default: latest)
#   --client-only       Install client only
#   --server-only       Install server only
#   --install-dir DIR   Installation directory (default: /usr/local/bin)
#   --service           Create system service (systemd/LaunchDaemon/rc.d)
#   --dry-run           Show what would be done without installing
#
# Supported: Linux (x86_64/aarch64/armv7), macOS (universal), FreeBSD (amd64/aarch64)

set -euo pipefail

ASSETS_BASE="https://assets.rvpn.org"
# ── Release trust anchors (compiled into this tagged installer, NOT fetched from the download host) ──
# The release public key (allowed_signers format) and the rollback floor are
# baked in here at tag time, so bucket write cannot move them. The installer
# verifies the signed aggregate manifest with ssh-keygen -Y verify (OpenSSH >= 8.0,
# preinstalled on macOS / Linux / FreeBSD) and FAILS CLOSED — there is no fallback
# to a per-artifact .sha256 from the bucket.
# RELEASE PUBKEY: the public half of the rVPN release signing key. The secret
# half is held in release custody. Rotating = new key + a new anchor here, in a
# new release; RVPN_MIN_VERSION below already keeps older manifests out.
RVPN_ALLOWED_SIGNERS='rvpn-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBvAJ88NBxirdpet6709kEOexDMzs9Mkw6i3ARNPu/Xi rvpn-release'
RVPN_SIGN_NAMESPACE="rvpn-release"
# Rollback floor: minimum acceptable release version. Bump at tag time
# (same ceremony as CORE_VERSION). A genuinely signed OLD release served by bucket
# write is refused because its signed manifest version is below this floor.
RVPN_MIN_VERSION="1.3.8"
VERIFIED_MANIFEST=""
MANIFEST_DIR=""
INSTALL_DIR="/usr/local/bin"
VERSION=""
INSTALL_CLIENT=true
INSTALL_SERVER=true
DRY_RUN=false
INTERACTIVE=false
CREATE_SERVICE=false
CONFIG_DIR=""
BIN_CLIENT="rvpn"
BIN_SERVER="rvpn-server"

# ── Platform Detection ──

detect_platform() {
    local os arch

    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux)
            CONFIG_DIR="/etc/rvpn"
            case "$arch" in
                x86_64)  BINARY="rvpn-x86_64-linux-gnu" ;;
                aarch64) BINARY="rvpn-aarch64-linux-gnu" ;;
                armv7l|armhf) BINARY="rvpn-armv7-linux" ;;
                *) echo "ERROR: Unsupported Linux architecture: $arch" >&2; exit 1 ;;
            esac
            ;;
        Darwin)
            CONFIG_DIR="/etc/rvpn"
            BINARY="rvpn-macos-universal"
            ;;
        FreeBSD)
            CONFIG_DIR="/usr/local/etc/rvpn"
            case "$arch" in
                amd64|x86_64) BINARY="rvpn-x86_64-freebsd" ;;
                aarch64) BINARY="rvpn-aarch64-freebsd" ;;
                *) echo "ERROR: Unsupported FreeBSD architecture: $arch" >&2; exit 1 ;;
            esac
            ;;
        *)
            echo "ERROR: Unsupported operating system: $os" >&2
            echo "Supported: Linux, macOS, FreeBSD" >&2
            exit 1
            ;;
    esac
}

# ── Colors ──

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

info()  { echo -e "${CYAN}ℹ $1${NC}"; }
ok()    { echo -e "${GREEN}✓ $1${NC}"; }
warn()  { echo -e "${YELLOW}⚠ $1${NC}"; }
error() { echo -e "${RED}✗ $1${NC}" >&2; }

# ── Helpers ──

resolve_version() {
    if [ -n "$VERSION" ]; then return; fi
    info "Fetching latest version..."
    VERSION=$(curl -fsSL --connect-timeout 10 --max-time 15 "$ASSETS_BASE/VERSION" 2>/dev/null || echo "")
    if [ -z "$VERSION" ]; then
        warn "Could not fetch latest version. Please specify --version"
        echo "Available versions: 1.0.4"
        exit 1
    fi
    ok "Latest version: $VERSION"
}

# Rollback floor: numeric dot-version compare — true if a < b (e.g. 1.3.7 < 1.3.8).
version_lt() {
    local a="$1" b="$2" i x y
    local IFS=.
    set -- $a; local aa=("$@")
    set -- $b; local bb=("$@")
    for i in 0 1 2; do
        x="${aa[$i]:-0}"; y="${bb[$i]:-0}"
        [ "$x" -lt "$y" ] && return 0
        [ "$x" -gt "$y" ] && return 1
    done
    return 1
}

# Fetch + verify the signed aggregate manifest ONCE, before any binary is
# trusted. Fail closed: absent/invalid manifest or signature, missing or pre-8.0
# OpenSSH, an unfilled release pubkey, or a version below the floor are all HARD
# failures. There is NO fallback to a per-artifact .sha256 (a degraded path is
# exactly the attacker's next move — make the manifest unavailable, drop to weaker).
verify_manifest() {
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would fetch + verify the signed manifest for $VERSION"
        return 0
    fi

    # The verifier must be a known quantity on the box: OpenSSH >= 8.0 (ed25519 -Y).
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        error "ssh-keygen not found."
        echo "  rVPN verifies the release manifest with OpenSSH (ssh-keygen -Y verify,"
        echo "  needs OpenSSH >= 8.0). Install OpenSSH and retry. Refusing to install unverified."
        return 1
    fi
    local sshver major
    sshver="$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
    if [ -n "$sshver" ]; then
        major="${sshver%%.*}"
        if [ "$major" -lt 8 ]; then
            error "OpenSSH $sshver is too old (need >= 8.0 for ssh-keygen -Y verify)."
            echo "  Upgrade OpenSSH and retry. Refusing to install unverified."
            return 1
        fi
    fi

    # Compiled-in trust anchor must be filled (fail closed on a placeholder build).
    case "$RVPN_ALLOWED_SIGNERS" in
        *REPLACE_WITH_RELEASE_PUBKEY*)
            error "This installer was built without the rVPN release public key."
            echo "  Refusing to install unverified. Use an official tagged installer from rvpn.org."
            return 1;;
    esac

    MANIFEST_DIR="$(mktemp -d)"
    trap 'rm -rf "$MANIFEST_DIR"' EXIT
    local mfile="$MANIFEST_DIR/SHA256SUMS.txt" sfile="$MANIFEST_DIR/SHA256SUMS.txt.sig" asfile="$MANIFEST_DIR/allowed_signers"

    if ! curl -fsSL --connect-timeout 10 --max-time 30 "$ASSETS_BASE/${VERSION}/SHA256SUMS.txt" -o "$mfile"; then
        error "Could not fetch the signed manifest for $VERSION."
        echo "  Looked for: $ASSETS_BASE/${VERSION}/SHA256SUMS.txt"
        echo "  Refusing to install without a verified manifest (no fallback). Retry or check $ASSETS_BASE."
        return 1
    fi
    if ! curl -fsSL --connect-timeout 10 --max-time 30 "$ASSETS_BASE/${VERSION}/SHA256SUMS.txt.sig" -o "$sfile"; then
        error "Could not fetch the manifest signature for $VERSION."
        echo "  Refusing to install without a verified manifest (no fallback)."
        return 1
    fi

    printf '%s\n' "$RVPN_ALLOWED_SIGNERS" > "$asfile"
    if ! ssh-keygen -Y verify -f "$asfile" -I "$RVPN_SIGN_NAMESPACE" -n "$RVPN_SIGN_NAMESPACE" -s "$sfile" < "$mfile" >/dev/null 2>&1; then
        error "Manifest signature verification FAILED for $VERSION."
        echo "  The release manifest is not signed by the rVPN release key. Refusing to install."
        echo "  (Hard failure — there is no weaker fallback check.)"
        return 1
    fi
    ok "Manifest signature verified (rvpn-release)"

    # Rollback floor: the signed manifest carries its version; refuse any
    # version below the floor baked into this tagged installer.
    local mver
    mver="$(grep -m1 '^# version: ' "$mfile" | awk '{print $3}')"
    if [ -z "$mver" ]; then
        error "Signed manifest carries no version header — cannot check the rollback floor. Refusing."
        return 1
    fi
    # Strict release version: X.Y.Z only. A suffixed version (e.g. 1.3.7-rc1)
    # makes version_lt's numeric tests error and fall through to "accepted" —
    # the floor must not depend on the signature alone.
    if ! [[ "$mver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Manifest version '$mver' is not a strict X.Y.Z release version. Refusing."
        return 1
    fi
    # The signed manifest must name the release we asked for: VERSION comes from
    # the bucket, so a valid signature for a different release is not a pass.
    if [ "$mver" != "$VERSION" ]; then
        error "Manifest version $mver does not match the requested release $VERSION. Refusing."
        return 1
    fi
    if version_lt "$mver" "$RVPN_MIN_VERSION"; then
        error "Manifest version $mver is below the minimum $RVPN_MIN_VERSION baked into this installer."
        echo "  Refusing a possible rollback to an older release. Use a current installer from rvpn.org."
        return 1
    fi
    VERIFIED_MANIFEST="$mfile"
    ok "Manifest version $mver accepted (floor $RVPN_MIN_VERSION)"
}

download_and_verify() {
    local name="$1"
    local dest="$2"
    local tmpfile

    tmpfile=$(mktemp)
    local url="$ASSETS_BASE/${VERSION}/${name}"

    info "Downloading $name"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would download: $url"
        echo "  [DRY RUN] Would install to: $dest"
        rm -f "$tmpfile"
        return 0
    fi

    # Download binary
    if ! curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$tmpfile"; then
        error "Failed to download $url"
        rm -f "$tmpfile"
        return 1
    fi

    # Verify against the SIGNED manifest (verified once in verify_manifest),
    # never a per-artifact .sha256 fetched from the bucket. No fallback.
    local expected_sha
    if [ -z "$VERIFIED_MANIFEST" ] || [ ! -f "$VERIFIED_MANIFEST" ]; then
        error "No verified manifest available — refusing to install $name unverified."
        rm -f "$tmpfile"
        return 1
    fi
    expected_sha="$(awk -v n="$name" '$2==n{print $1}' "$VERIFIED_MANIFEST")"
    if [ -z "$expected_sha" ]; then
        error "$name is not listed in the signed manifest — refusing to install."
        rm -f "$tmpfile"
        return 1
    fi

    local actual_sha
    if command -v sha256sum &>/dev/null; then
        actual_sha=$(sha256sum "$tmpfile" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        actual_sha=$(shasum -a 256 "$tmpfile" | awk '{print $1}')
    elif command -v sha256 &>/dev/null; then
        actual_sha=$(sha256 -q "$tmpfile")
    else
        actual_sha=""
    fi

    if [ -z "$actual_sha" ]; then
        error "No SHA256 tool found (need sha256sum, shasum, or sha256)"
        echo "  Refusing to install an unverified binary."
        rm -f "$tmpfile"
        return 1
    fi

    if [ "$expected_sha" = "$actual_sha" ]; then
        ok "SHA256 verified"
    else
        error "SHA256 mismatch for $name"
        echo "  Expected: $expected_sha"
        echo "  Actual:   $actual_sha"
        rm -f "$tmpfile"
        return 1
    fi

    chmod +x "$tmpfile"

    # macOS: remove quarantine attribute
    if [ "$(uname -s)" = "Darwin" ]; then
        xattr -d com.apple.quarantine "$tmpfile" 2>/dev/null || true
    fi

    mv "$tmpfile" "$dest"
    ok "Installed to $dest"
}

# ── Service Creation ──

create_service() {
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would create system service"
        return
    fi

    local os
    os=$(uname -s)

    case "$os" in
        Linux)
            if command -v systemctl >/dev/null 2>&1; then
                if [ "$INSTALL_CLIENT" = true ]; then
                    cat > /etc/systemd/system/rvpn-client.service << 'EOF'
[Unit]
Description=R-VPN Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rvpn -c /etc/rvpn/client.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
                    ok "Created systemd service: rvpn-client"
                fi
                if [ "$INSTALL_SERVER" = true ]; then
                    cat > /etc/systemd/system/rvpn-server.service << 'EOF'
[Unit]
Description=R-VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rvpn-server -c /etc/rvpn/server.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
                    ok "Created systemd service: rvpn-server"
                fi
                systemctl daemon-reload
            fi
            ;;
        Darwin)
            if [ "$INSTALL_CLIENT" = true ]; then
                cat > /Library/LaunchDaemons/com.rvpn.client.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.rvpn.client</string>
    <key>ProgramArguments</key>
    <array><string>/usr/local/bin/rvpn</string><string>-c</string><string>/etc/rvpn/client.toml</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/var/log/rvpn-client.log</string>
    <key>StandardErrorPath</key><string>/var/log/rvpn-client.log</string>
</dict>
</plist>
EOF
                ok "Created LaunchDaemon: com.rvpn.client"
            fi
            if [ "$INSTALL_SERVER" = true ]; then
                cat > /Library/LaunchDaemons/com.rvpn.server.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.rvpn.server</string>
    <key>ProgramArguments</key>
    <array><string>/usr/local/bin/rvpn-server</string><string>-c</string><string>/etc/rvpn/server.toml</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/var/log/rvpn-server.log</string>
    <key>StandardErrorPath</key><string>/var/log/rvpn-server.log</string>
</dict>
</plist>
EOF
                ok "Created LaunchDaemon: com.rvpn.server"
            fi
            ;;
        FreeBSD)
            if [ "$INSTALL_CLIENT" = true ]; then
                cat > /usr/local/etc/rc.d/rvpn_client << 'SCRIPT'
#!/bin/sh
# PROVIDE: rvpn_client
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name="rvpn_client"
rcvar="rvpn_client_enable"
command="/usr/local/sbin/daemon"
daemon_flags="-f -p /var/run/rvpn-client.pid"
procname="/usr/local/bin/rvpn"
command_args="-f -p /var/run/rvpn-client.pid -- /usr/local/bin/rvpn -c /usr/local/etc/rvpn/client.toml"
pidfile="/var/run/rvpn-client.pid"
load_rc_config $name
: ${rvpn_client_enable="NO"}
run_rc_command "$1"
SCRIPT
                chmod +x /usr/local/etc/rc.d/rvpn_client
                ok "Created rc.d: rvpn_client"
            fi
            if [ "$INSTALL_SERVER" = true ]; then
                cat > /usr/local/etc/rc.d/rvpn_server << 'SCRIPT'
#!/bin/sh
# PROVIDE: rvpn_server
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name="rvpn_server"
rcvar="rvpn_server_enable"
command="/usr/local/sbin/daemon"
command_args="-f -p /var/run/rvpn-server.pid -- /usr/local/bin/rvpn-server -c /usr/local/etc/rvpn/server.toml"
pidfile="/var/run/rvpn-server.pid"
load_rc_config $name
: ${rvpn_server_enable="NO"}
run_rc_command "$1"
SCRIPT
                chmod +x /usr/local/etc/rc.d/rvpn_server
                ok "Created rc.d: rvpn_server"
            fi
            ;;
    esac
}

# ── Config Setup ──

setup_config() {
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would create config directory: $CONFIG_DIR"
        return
    fi

    local mkdir_cmd="mkdir"
    if [ "$(uname -s)" = "Darwin" ]; then
        mkdir_cmd="sudo mkdir"
    fi

    $mkdir_cmd -p "$CONFIG_DIR" 2>/dev/null || mkdir -p "$CONFIG_DIR"

    # Skip default config creation in interactive mode — server_setup()/client_setup() handle it
    if [ "$INSTALL_CLIENT" = true ] && [ ! -f "$CONFIG_DIR/client.toml" ] && [ "$INTERACTIVE" = false ]; then
        cat > "$CONFIG_DIR/client.toml" << 'EOF'
server_address = "wss://your-server.com/api/v1/ws"
identity_key_file = "/etc/rvpn/identity.key"
prekey_bundle = "/etc/rvpn/prekey-bundle.json"
tls_fingerprint = "Chrome"

[server_identity]
trust_on_first_use = true
known_hosts_file = "/var/lib/rvpn/known_hosts.json"
strict = false

[socks5]
listen_address = "127.0.0.1:1080"
udp_associate = true

[split_tunnel]
enabled = false
EOF
        # Normalize paths for FreeBSD
        if [ "$(uname -s)" = "FreeBSD" ]; then
            sed -i '' \
                -e 's|/etc/rvpn/|/usr/local/etc/rvpn/|g' \
                -e 's|/var/lib/rvpn/|/var/db/rvpn/|g' \
                "$CONFIG_DIR/client.toml"
        fi
        ok "Created example config: $CONFIG_DIR/client.toml"
    fi

    # Skip default config creation in interactive mode — server_setup()/client_setup() handle it
    if [ "$INSTALL_SERVER" = true ] && [ ! -f "$CONFIG_DIR/server.toml" ] && [ "$INTERACTIVE" = false ]; then
        cat > "$CONFIG_DIR/server.toml" << 'EOF'
[server]
bind_address = "0.0.0.0:443"
identity_key_file = "/etc/rvpn/server_identity.key"
prekey_bundle_file = "/etc/rvpn/prekey-bundle.json"
websocket_path = "/api/v1/ws"

[server.tun]
enabled = true
tun_ip = "10.200.0.1/24"
mtu = 1420

[server.network]
nat_enabled = true
dns_servers = ["1.1.1.1", "8.8.8.8"]
EOF
        if [ "$(uname -s)" = "FreeBSD" ]; then
            sed -i '' 's|/etc/rvpn/|/usr/local/etc/rvpn/|g' "$CONFIG_DIR/server.toml"
        fi
        ok "Created example config: $CONFIG_DIR/server.toml"
    fi
}

# ── Let's Encrypt Certificate Detection ──

detect_letsencrypt_certs() {
    local certs_dir="/etc/letsencrypt/live"
    local result=""

    if [ ! -d "$certs_dir" ]; then
        echo ""
        return
    fi

    for domain_dir in "$certs_dir"/*/; do
        if [ -d "$domain_dir" ] && [ -f "${domain_dir}fullchain.pem" ] && [ -f "${domain_dir}privkey.pem" ]; then
            local domain
            domain=$(basename "$domain_dir")
            if [ -n "$result" ]; then
                result="$result $domain"
            else
                result="$domain"
            fi
        fi
    done

    echo "$result"
}

prompt_tls_config() {
    # Outputs — one of these three combinations is set by end of function:
    #   1. ACME_ENABLED=true + ACME_DOMAIN + ACME_EMAIL + ACME_STAGING + ACME_CACHE_DIR (built-in Let's Encrypt)
    #   2. TLS_CERT_FILE + TLS_KEY_FILE (BYO cert — e.g. existing certbot)
    #   3. all empty (behind reverse proxy or user configures manually later)
    ACME_ENABLED=""
    ACME_DOMAIN=""
    ACME_EMAIL=""
    ACME_STAGING="false"
    ACME_CACHE_DIR=""
    TLS_CERT_FILE=""
    TLS_KEY_FILE=""

    echo ""
    echo "  TLS mode:"
    echo "    1) Automatic — rvpn-server obtains and renews a Let's Encrypt cert itself"
    echo "       (recommended; needs port 443 reachable and a public A/AAAA record)"
    echo "    2) Use an existing certificate on disk (e.g. from certbot)"
    echo "    3) None — TLS terminated elsewhere (reverse proxy, or configure later)"
    echo ""

    local tls_mode
    printf "  Choose (1/2/3) [1]: " > /dev/tty; read tls_mode < /dev/tty
    tls_mode=${tls_mode:-1}

    case "$tls_mode" in
        1)
            prompt_acme_config
            ;;
        2)
            prompt_static_cert_config
            ;;
        *)
            ok "Skipping TLS setup. Configure tls_cert_file / tls_key_file or [server.acme] later."
            ;;
    esac
}

# Interactive: collect [server.acme] settings and prepare the cache directory.
prompt_acme_config() {
    local domain
    printf "  Domain name (must resolve to this server): " > /dev/tty; read domain < /dev/tty
    if [ -z "$domain" ]; then
        warn "No domain provided. Skipping TLS setup."
        return
    fi

    local email
    printf "  Contact email (for Let's Encrypt expiry notices): " > /dev/tty; read email < /dev/tty

    local staging_default="Y"
    echo ""
    echo "  Let's Encrypt has a 5-failed-authorizations-per-hour rate limit."
    echo "  First-run recommended: use the staging environment to prove the setup"
    echo "  works, then flip to production. Staging certs are not browser-trusted."
    local staging_input
    printf "  Start with Let's Encrypt staging? (${staging_default}/n): " > /dev/tty; read staging_input < /dev/tty
    if case "$staging_input" in [Nn]*) true;; *) false;; esac; then
        ACME_STAGING="false"
        ACME_CACHE_DIR="/var/lib/rvpn/acme"
    else
        ACME_STAGING="true"
        # Different cache dir keeps staging and production certs apart, so
        # flipping `staging = false` doesn't reuse an untrusted-account cert.
        ACME_CACHE_DIR="/var/lib/rvpn/acme-staging"
    fi

    ACME_ENABLED="true"
    ACME_DOMAIN="$domain"
    ACME_EMAIL="$email"

    # Best-effort directory setup so the service can write on first boot.
    mkdir -p "$ACME_CACHE_DIR" 2>/dev/null || sudo mkdir -p "$ACME_CACHE_DIR"
    chmod 700 "$ACME_CACHE_DIR" 2>/dev/null || sudo chmod 700 "$ACME_CACHE_DIR"

    local env_label="production"
    [ "$ACME_STAGING" = "true" ] && env_label="staging"
    ok "ACME configured for $domain ($env_label directory, cache at $ACME_CACHE_DIR)"
    if [ "$ACME_STAGING" = "true" ]; then
        echo ""
        echo "  After you see \"ACME event: CertCacheStore\" in the journal, edit"
        echo "  $CONFIG_DIR/server.toml to set staging = false and change cache_dir"
        echo "  to /var/lib/rvpn/acme, then restart the service."
    fi
}

# Interactive: pick an existing cert on disk (certbot or otherwise).
prompt_static_cert_config() {
    local found_certs
    found_certs=$(detect_letsencrypt_certs)

    if [ -n "$found_certs" ]; then
        echo ""
        info "Found existing Let's Encrypt certificates:"
        local i=1
        local cert_count=0
        for cert_domain in $found_certs; do
            local expiry
            expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${cert_domain}/fullchain.pem" 2>/dev/null | cut -d= -f2 || echo "unknown")
            echo "    $i) $cert_domain (expires: $expiry)"
            cert_count=$((cert_count + 1))
            i=$((i + 1))
        done

        echo ""
        local selection=1
        if [ "$cert_count" -gt 1 ]; then
            printf "  Which certificate? [1-%d] (1): " "$cert_count" > /dev/tty; read selection < /dev/tty
            selection=${selection:-1}
        fi
        local chosen=""
        local j=1
        for cert_domain in $found_certs; do
            if [ "$j" -eq "$selection" ]; then
                chosen="$cert_domain"
                break
            fi
            j=$((j + 1))
        done
        if [ -n "$chosen" ]; then
            TLS_CERT_FILE="/etc/letsencrypt/live/${chosen}/fullchain.pem"
            TLS_KEY_FILE="/etc/letsencrypt/live/${chosen}/privkey.pem"
            ok "Using certificate for: $chosen"
            echo "  Remember to add a certbot deploy hook that restarts rvpn-server on renewal."
            return
        fi
    fi

    # No detected cert — ask for explicit paths.
    echo ""
    warn "No Let's Encrypt certificates detected under /etc/letsencrypt/live/."
    local cert_path key_path
    printf "  Path to fullchain PEM (blank to skip): " > /dev/tty; read cert_path < /dev/tty
    if [ -z "$cert_path" ]; then
        ok "Skipping TLS setup."
        return
    fi
    printf "  Path to private key PEM: " > /dev/tty; read key_path < /dev/tty
    if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
        TLS_CERT_FILE="$cert_path"
        TLS_KEY_FILE="$key_path"
        ok "Static certificate configured: $cert_path"
    fi
}

# ── Interactive Server Setup ──

server_setup() {
    local os
    os=$(uname -s)
    local cfg="$CONFIG_DIR/server.toml"

    echo ""
    echo "── R-VPN Server Setup ──"
    echo ""

    # Bind address
    local bind_addr
    printf "  Bind address (0.0.0.0:443): " > /dev/tty; read bind_addr < /dev/tty
    bind_addr=${bind_addr:-0.0.0.0:443}

    # WebSocket path
    local ws_path
    printf "  WebSocket path (/api/v1/ws): " > /dev/tty; read ws_path < /dev/tty
    ws_path=${ws_path:-/api/v1/ws}

    # TUN mode
    local tun_enabled="true"
    printf "  Enable TUN mode (full VPN)? (Y/n): " > /dev/tty; read tun_input < /dev/tty
    if case "$tun_input" in [Nn]*) true;; *) false;; esac; then
        tun_enabled="false"
    fi

    # TUN IP
    local tun_ip="10.200.0.1/24"
    if [ "$tun_enabled" = "true" ]; then
        printf "  TUN IP range ($tun_ip): " > /dev/tty; read tun_ip_in < /dev/tty
        tun_ip=${tun_ip_in:-$tun_ip}
    fi

    # NAT
    local nat_enabled="true"
    if [ "$tun_enabled" = "true" ]; then
        printf "  Enable NAT for client traffic? (Y/n): " > /dev/tty; read nat_input < /dev/tty
        if case "$nat_input" in [Nn]*) true;; *) false;; esac; then
            nat_enabled="false"
        fi
    fi

    # DNS
    local dns_servers="1.1.1.1, 8.8.8.8"
    if [ "$tun_enabled" = "true" ]; then
        printf "  DNS servers for clients ($dns_servers): " > /dev/tty; read dns_input < /dev/tty
        dns_servers=${dns_input:-$dns_servers}
    fi

    # Generate keys
    local gen_key="true"
    printf "  Generate server identity key? (Y/n): " > /dev/tty; read key_input < /dev/tty
    if case "$key_input" in [Nn]*) true;; *) false;; esac; then
        gen_key="false"
    fi

    local gen_prekey="true"
    printf "  Generate prekey bundle? (Y/n): " > /dev/tty; read pk_input < /dev/tty
    if case "$pk_input" in [Nn]*) true;; *) false;; esac; then
        gen_prekey="false"
    fi

    # TLS certificate configuration
    prompt_tls_config

    echo ""
    info "Writing configuration..."

    # Warn if config already exists
    if [ -f "$cfg" ]; then
        warn "Existing config found: $cfg"
        printf "  Overwrite existing config? (y/N): " > /dev/tty; read overwrite_input < /dev/tty
        if case "$overwrite_input" in [Yy]*) false;; *) true;; esac; then
            ok "Keeping existing config: $cfg"
            echo ""
            return
        fi
    fi

    # Format DNS servers as TOML array
    local dns_toml
    dns_toml=$(echo "$dns_servers" | sed 's/, */, /g' | awk -F', ' '{
        printf "["
        for (i=1; i<=NF; i++) {
            if (i > 1) printf ", "
            printf "\"%s\"", $i
        }
        printf "]"
    }')

    cat > "$cfg" << EOF
[server]
bind_address = "$bind_addr"
identity_key_file = "$CONFIG_DIR/server_identity.key"
prekey_bundle_file = "$CONFIG_DIR/prekey-bundle.json"
websocket_path = "$ws_path"
EOF

    # Add TLS config under [server] if certificates were configured
    if [ -n "$TLS_CERT_FILE" ] && [ -n "$TLS_KEY_FILE" ]; then
        cat >> "$cfg" << EOF
tls_cert_file = "$TLS_CERT_FILE"
tls_key_file = "$TLS_KEY_FILE"
EOF
    fi

    # ACME (built-in Let's Encrypt) block if the user picked automatic TLS
    if [ "$ACME_ENABLED" = "true" ]; then
        local contact_line=""
        if [ -n "$ACME_EMAIL" ]; then
            contact_line="contacts  = [\"mailto:$ACME_EMAIL\"]"
        else
            contact_line="contacts  = []"
        fi
        cat >> "$cfg" << EOF

[server.acme]
enabled   = true
domains   = ["$ACME_DOMAIN"]
$contact_line
cache_dir = "$ACME_CACHE_DIR"
staging   = $ACME_STAGING
EOF
    fi

    cat >> "$cfg" << EOF

[server.tun]
enabled = $tun_enabled
tun_ip = "$tun_ip"
mtu = 1420

[server.network]
nat_enabled = $nat_enabled
dns_servers = $dns_toml
EOF

    ok "Config written: $cfg"

    # Generate keys
    if [ "$gen_key" = "true" ]; then
        info "Generating server identity key..."
        "$INSTALL_DIR/rvpn-server" -c "$cfg" keygen -o "$CONFIG_DIR/server_identity.key"
        ok "Identity key: $CONFIG_DIR/server_identity.key"

        local fp
        fp=$(cat "$CONFIG_DIR/server_identity.key" | head -1 | cut -d: -f2- 2>/dev/null || echo "(check file)")
        info "Server fingerprint: $fp"
        echo ""
        echo "  Share this fingerprint with clients for identity verification."
    fi

    if [ "$gen_prekey" = "true" ]; then
        info "Generating prekey bundle..."
        "$INSTALL_DIR/rvpn-server" -c "$cfg" prekey-bundle \
            --identity "$CONFIG_DIR/server_identity.key" \
            --output "$CONFIG_DIR/prekey-bundle.json"
        ok "Prekey bundle: $CONFIG_DIR/prekey-bundle.json"
    fi

    if [ "$tun_enabled" = "true" ]; then
        echo ""
        case "$os" in
            Linux)
                info "Enable net.ipv4.ip_forward=1 and install iptables/ip6tables before starting."
                info "The server creates owned RVPN_* containment chains and optional NAT at startup."
                ;;
            FreeBSD)
                warn "TUN requires PF enabled, forwarding enabled, and these active /etc/pf.conf entries before broad quick passes:"
                echo '      nat-anchor "rvpn"'
                echo '      anchor "rvpn"'
                echo "    The server validates and loads only the rvpn anchor; it never replaces main PF rules."
                ;;
        esac
    fi

    echo ""
    echo "══════════════════════════════════════════════════════════"
    ok "Server setup complete!"
    echo "══════════════════════════════════════════════════════════"

    # Offer to create service
    local svc_input
    printf "  Create systemd/LaunchDaemon service? (Y/n): " > /dev/tty; read svc_input < /dev/tty
    if case "$svc_input" in [Nn]*) false;; *) true;; esac; then
        CREATE_SERVICE=true
        create_service
        echo ""
        echo "  To start the server:"
        case "$os" in
            Linux)   echo "  systemctl enable --now rvpn-server" ;;
            Darwin)  echo "  sudo launchctl load /Library/LaunchDaemons/com.rvpn.server.plist" ;;
            FreeBSD) echo "  sysrc rvpn_server_enable=YES && service rvpn_server start" ;;
        esac
    fi

    echo ""
    echo "For client installations, share the prekey bundle at:"
    echo "  $CONFIG_DIR/prekey-bundle.json"
    echo ""
    echo "And the server identity fingerprint:"
    if [ -f "$CONFIG_DIR/server_identity.key" ]; then
        local fp
        fp=$(cat "$CONFIG_DIR/server_identity.key" | head -1 | cut -d: -f2-)
        echo "  $fp"
    fi

    echo ""
    echo "  Edit config if needed: nano $cfg"
}

# ── Interactive Client Setup ──

client_setup() {
    local os
    os=$(uname -s)
    local cfg="$CONFIG_DIR/client.toml"

    echo ""
    echo "── R-VPN Client Setup ──"
    echo ""

    # Server address
    local server_addr
    printf "  Server address (wss://your-server.com/api/v1/ws): " > /dev/tty; read server_addr < /dev/tty
    if [ -z "$server_addr" ]; then
        server_addr="wss://your-server.com/api/v1/ws"
        warn "Remember to update the server address in $cfg"
    fi

    # SOCKS5 listen
    local socks5_addr="127.0.0.1:1080"
    printf "  SOCKS5 listen address ($socks5_addr): " > /dev/tty; read socks5_in < /dev/tty
    socks5_addr=${socks5_in:-$socks5_addr}

    # Split tunnel
    local split_enabled="false"
    printf "  Enable split tunnel (route only certain traffic through VPN)? (y/N): " > /dev/tty; read split_input < /dev/tty
    if case "$split_input" in [Yy]*) true;; *) false;; esac; then
        split_enabled="true"
    fi

    # DNS proxy
    local dns_enabled="true"
    printf "  Enable DNS proxy (resolve DNS through VPN)? (Y/n): " > /dev/tty; read dns_input < /dev/tty
    if case "$dns_input" in [Nn]*) true;; *) false;; esac; then
        dns_enabled="false"
    fi

    # TLS fingerprint
    local tls_fp="Chrome"
    printf "  TLS fingerprint (Chrome/Firefox/Safari/None) ($tls_fp): " > /dev/tty; read tls_in < /dev/tty
    tls_fp=${tls_in:-$tls_fp}

    # Generate identity key
    local gen_key="true"
    printf "  Generate client identity key? (Y/n): " > /dev/tty; read key_input < /dev/tty
    if case "$key_input" in [Nn]*) true;; *) false;; esac; then
        gen_key="false"
    fi

    echo ""
    info "Writing configuration..."

    # Warn if config already exists
    if [ -f "$cfg" ]; then
        warn "Existing config found: $cfg"
        printf "  Overwrite existing config? (y/N): " > /dev/tty; read overwrite_input < /dev/tty
        if case "$overwrite_input" in [Yy]*) false;; *) true;; esac; then
            ok "Keeping existing config: $cfg"
            echo ""
            return
        fi
    fi

    cat > "$cfg" << EOF
server_address = "$server_addr"
identity_key_file = "$CONFIG_DIR/identity.key"
prekey_bundle = "$CONFIG_DIR/prekey-bundle.json"
tls_fingerprint = "$tls_fp"

[server_identity]
trust_on_first_use = true
known_hosts_file = "/var/lib/rvpn/known_hosts.json"
strict = false

[socks5]
listen_address = "$socks5_addr"
udp_associate = true

[split_tunnel]
enabled = $split_enabled
EOF

    # Add DNS proxy section if enabled
    if [ "$dns_enabled" = "true" ]; then
        cat >> "$cfg" << EOF

[dns_proxy]
enabled = true
listen_address = "127.0.0.1:53"
EOF
    fi

    ok "Config written: $cfg"

    # Generate key
    if [ "$gen_key" = "true" ]; then
        info "Generating client identity key..."
        "$INSTALL_DIR/rvpn" keygen -o "$CONFIG_DIR/identity.key"
        ok "Identity key: $CONFIG_DIR/identity.key"
    fi

    echo ""
    echo "══════════════════════════════════════════════════════════"
    ok "Client setup complete!"
    echo "══════════════════════════════════════════════════════════"

    echo ""
    echo "  Next: copy the server's prekey-bundle.json to:"
    echo "    $CONFIG_DIR/prekey-bundle.json"

    # Offer to create service
    local svc_input
    printf "  Create systemd/LaunchDaemon service? (Y/n): " > /dev/tty; read svc_input < /dev/tty
    if case "$svc_input" in [Nn]*) false;; *) true;; esac; then
        CREATE_SERVICE=true
        create_service
        echo ""
        echo "  To start the client:"
        case "$os" in
            Linux)   echo "  systemctl enable --now rvpn-client" ;;
            Darwin)  echo "  sudo launchctl load /Library/LaunchDaemons/com.rvpn.client.plist" ;;
            FreeBSD) echo "  sysrc rvpn_client_enable=YES && service rvpn_client start" ;;
        esac
    else
        echo ""
        echo "  To start the client manually:"
        echo "  rvpn -c $cfg"
    fi

    echo ""
    echo "  Edit config if needed: nano $cfg"
}

# ── Root Check ──

check_root() {
    local uid
    uid=$(id -u 2>/dev/null || echo "$(id -u)")
    if [ "$uid" -ne 0 ]; then
        if [ "$DRY_RUN" = true ]; then
            warn "Would require root for installation to $INSTALL_DIR"
            return 0
        fi
        error "This script must be run as root (or with sudo)"
        echo "Usage: curl -fsSL https://assets.rvpn.org/install.sh | sudo bash"
        exit 1
    fi
}

# ── Usage ──

usage() {
    echo "R-VPN Universal Installer"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION   Install specific version (default: latest)"
    echo "  --client-only       Install client only"
    echo "  --server-only       Install server only"
    echo "  --server            Alias for --server-only"
    echo "  --client            Alias for --client-only"
    echo "  --install-dir DIR   Installation directory (default: /usr/local/bin)"
    echo "  --service           Create system service (systemd/LaunchDaemon/rc.d)"
    echo "  --setup             Interactive setup (configure server/client)"
    echo "  --dry-run           Show what would be done"
    echo "  -h, --help          Show this help"
}

# ── Main ──

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --client-only) INSTALL_SERVER=false; shift ;;
        --server-only) INSTALL_CLIENT=false; shift ;;
        --server) INSTALL_CLIENT=false; shift ;;
        --client) INSTALL_SERVER=false; shift ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --service) CREATE_SERVICE=true; shift ;;
        --setup) INTERACTIVE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Prompt if neither --server nor --client was specified
if [ "$INSTALL_CLIENT" = true ] && [ "$INSTALL_SERVER" = true ]; then
    echo ""
    echo "What would you like to install?"
    echo "  1) Client only   (SOCKS5 proxy — route traffic through VPN)"
    echo "  2) Server only   (VPN endpoint — accept client connections)"
    echo "  3) Both          (default)"
    echo ""
    printf "  Choose [1/2/3] (3): " > /dev/tty; read choice < /dev/tty
    case "$choice" in
        1) INSTALL_SERVER=false; echo "  → Installing client only" ;;
        2) INSTALL_CLIENT=false; echo "  → Installing server only" ;;
        *) echo "  → Installing both" ;;
    esac
    echo ""
fi

detect_platform
OS=$(uname -s)
ARCH=$(uname -m)

echo -e "${CYAN}"
cat << 'BANNER'

    ██████╗ ██╗   ██╗██████╗ ███╗   ██╗
    ██╔══██╗██║   ██║██╔══██╗████╗  ██║
    ██████╔╝██║   ██║██████╔╝██╔██╗ ██║
    ██╔══██╗╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
    ██║  ██║ ╚████╔╝ ██║     ██║ ╚████║
    ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝

BANNER
echo -e "${NC}"
echo "  Encrypted VPN • Zero Knowledge • Open Source"
echo ""
info "OS:       $OS ($ARCH)"
info "Binary:   $BINARY"
info "Install:  $INSTALL_DIR"

check_root

# ── Detect existing installation ──

existing_version=""

for bin in "$INSTALL_DIR/rvpn" "$INSTALL_DIR/rvpn-server"; do
    if [ -x "$bin" ]; then
        bin_version=$("$bin" --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "")
        if [ -n "$bin_version" ]; then
            if [ -n "$existing_version" ] && [ "$bin_version" != "$existing_version" ]; then
                warn "Version mismatch: rvpn vs rvpn-server differ"
            fi
            existing_version="$bin_version"
        fi
    fi
done

resolve_version

if [ -n "$existing_version" ]; then
    echo ""
    info "Existing installation detected:"
    if [ "$INSTALL_CLIENT" = true ] && [ -x "$INSTALL_DIR/rvpn" ]; then
        cv=$("$INSTALL_DIR/rvpn" --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "?")
        echo "  rvpn:        $INSTALL_DIR/rvpn ($cv)"
    fi
    if [ "$INSTALL_SERVER" = true ] && [ -x "$INSTALL_DIR/rvpn-server" ]; then
        sv=$("$INSTALL_DIR/rvpn-server" --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "?")
        echo "  rvpn-server: $INSTALL_DIR/rvpn-server ($sv)"
    fi

    if [ "$existing_version" = "$VERSION" ]; then
        echo ""
        info "Version $VERSION is already installed."
        printf "  Reinstall anyway? (y/N): " > /dev/tty; read reinstall_input < /dev/tty
        if case "$reinstall_input" in [Yy]*) false;; *) true;; esac; then
            info "Skipping installation. Config is at $CONFIG_DIR/"
            echo ""
            if [ "$INSTALL_CLIENT" = true ]; then
                echo "  Edit config: nano $CONFIG_DIR/client.toml"
                echo "  Start:       rvpn -c $CONFIG_DIR/client.toml"
            fi
            if [ "$INSTALL_SERVER" = true ]; then
                if [ "$INSTALL_CLIENT" = true ]; then echo ""; fi
                echo "  Edit config: nano $CONFIG_DIR/server.toml"
                echo "  Start:       rvpn-server -c $CONFIG_DIR/server.toml"
            fi
            exit 0
        fi
        echo ""
    else
        echo ""
        info "Upgrading from $existing_version to $VERSION..."
    fi
fi

# Detect server binary name
SERVER_BINARY="$BINARY"
SERVER_BINARY=$(echo "$SERVER_BINARY" | sed 's/^rvpn-/rvpn-server-/')

# Verify the signed release manifest once, before any binary is trusted.
verify_manifest

echo ""
if [ "$INSTALL_CLIENT" = true ]; then
    echo "── Client ──"
    download_and_verify "$BINARY" "$INSTALL_DIR/rvpn"
fi

if [ "$INSTALL_SERVER" = true ]; then
    echo ""
    echo "── Server ──"
    download_and_verify "$SERVER_BINARY" "$INSTALL_DIR/rvpn-server"
fi

echo ""
echo "── Configuration ──"
setup_config

if [ "$CREATE_SERVICE" = true ]; then
    echo ""
    echo "── System Service ──"
    create_service
fi

if [ "$INTERACTIVE" = true ]; then
    if [ "$INSTALL_SERVER" = true ]; then
        server_setup
    fi
    if [ "$INSTALL_CLIENT" = true ]; then
        client_setup
    fi
else
    echo ""
    echo "══════════════════════════════════════════════════════════"
    ok "R-VPN v${VERSION} installed successfully!"
    echo "══════════════════════════════════════════════════════════"
    echo ""
    echo "Next steps:"

    if [ "$INSTALL_CLIENT" = true ]; then
        echo "  1. Generate key:   $( [ "$OS" = "Darwin" ] && echo "sudo " )rvpn keygen -o $CONFIG_DIR/identity.key"
        echo "  2. Get prekey bundle from server admin"
        echo "  3. Edit config:    $( [ "$OS" = "Darwin" ] && echo "sudo " )nano $CONFIG_DIR/client.toml"
        if [ "$CREATE_SERVICE" = true ]; then
            case "$OS" in
                Linux)   echo "  4. Start:          systemctl enable --now rvpn-client" ;;
                Darwin)  echo "  4. Start:          sudo launchctl load /Library/LaunchDaemons/com.rvpn.client.plist" ;;
                FreeBSD) echo "  4. Enable:         sysrc rvpn_client_enable=YES && service rvpn_client start" ;;
            esac
        else
            echo "  4. Start:          rvpn -c $CONFIG_DIR/client.toml"
        fi
    fi

    if [ "$INSTALL_SERVER" = true ]; then
        if [ "$INSTALL_CLIENT" = true ]; then echo ""; fi
        echo "  1. Generate key:   $( [ "$OS" = "Darwin" ] && echo "sudo " )rvpn-server keygen"
        echo "  2. Prekey bundle:  $( [ "$OS" = "Darwin" ] && echo "sudo " )rvpn-server prekey-bundle"
        echo "  3. Edit config:    $( [ "$OS" = "Darwin" ] && echo "sudo " )nano $CONFIG_DIR/server.toml"
        if [ "$OS" = "Linux" ]; then
            echo "     TUN: enable forwarding + install iptables/ip6tables; the server manages RVPN_* chains and NAT"
        elif [ "$OS" = "FreeBSD" ]; then
            echo "     TUN: enable PF/forwarding; add nat-anchor \"rvpn\" and anchor \"rvpn\" before broad quick passes"
            echo "     Load main rules yourself; the server only validates/loads the rvpn anchor"
        fi
        if [ "$CREATE_SERVICE" = true ]; then
            case "$OS" in
                Linux)   echo "  4. Start:          systemctl enable --now rvpn-server" ;;
                Darwin)  echo "  4. Start:          sudo launchctl load /Library/LaunchDaemons/com.rvpn.server.plist" ;;
                FreeBSD) echo "  4. Enable:         sysrc rvpn_server_enable=YES && service rvpn_server start" ;;
            esac
        else
            echo "  4. Start:          $( [ "$OS" = "Darwin" ] && echo "sudo " )rvpn-server -c $CONFIG_DIR/server.toml"
        fi
    fi
fi
