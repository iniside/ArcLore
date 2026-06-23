#!/usr/bin/env bash
#
# install.sh — one-command installer for the self-hosted ArcLore control plane.
#
# Installs TWO of OUR Go services:
#   * arc-lore-auth  — JWKS + gRPC auth (HTTP :8080, gRPC TLS :8443)
#   * ArcLoreWeb     — web frontend     (HTTP :41380 by default)
#
# It does NOT install Epic's lore-server (Rust) — that is deployed separately by
# the operator. It DOES optionally patch the existing lore-server config to point
# at this auth service (JWKS endpoint, audience, auth_url, SSL_CERT_FILE bundle).
#
# Workflow:
#   git clone https://github.com/iniside/ArcLore.git
#   sudo ./ArcLore/arclore-deploy/install.sh        # builds from sibling dirs
# OR (standalone, install.sh downloaded alone):
#   sudo ./install.sh                               # clones ArcLore, builds
#
# Run as root. Strict mode. Every destructive / Epic-service-touching step is
# confirmed individually.

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_OK=$'\033[32m'
    C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_BOLD=''
fi
log()   { printf '%s[*]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_OK"   "$C_RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
err()   { printf '%s[x]%s %s\n' "$C_ERR"  "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }
hdr()   { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_RESET"; }

# Confirm; returns 0 (yes) / 1 (no). Default No unless $2 == "Y".
confirm() {
    local prompt="$1" def="${2:-N}" reply
    if [[ "$ASSUME_YES" == "1" ]]; then
        # -y accepts safe defaults; it does NOT auto-approve Epic-service edits.
        [[ "$def" == "Y" ]] && return 0 || return 1
    fi
    local hint="[y/N]"; [[ "$def" == "Y" ]] && hint="[Y/n]"
    read -r -p "$prompt $hint " reply || true
    reply="${reply:-$def}"
    [[ "$reply" =~ ^[Yy] ]]
}

# Prompt for a value with a default; honours env override + -y.
ask() {
    # ask <varname> <prompt> <default>
    local __var="$1" __prompt="$2" __def="$3" __cur __reply
    __cur="${!__var:-}"
    if [[ -n "$__cur" ]]; then
        # Pre-set via environment — keep it, just report.
        log "$__prompt = ${!__var} (from environment)"
        return 0
    fi
    if [[ "$ASSUME_YES" == "1" ]]; then
        printf -v "$__var" '%s' "$__def"
        log "$__prompt = $__def (default)"
        return 0
    fi
    read -r -p "$__prompt [$__def]: " __reply || true
    printf -v "$__var" '%s' "${__reply:-$__def}"
}

rand_hex() { openssl rand -hex "${1:-32}"; }

# toml_set FILE TABLE KEY VALUE — set KEY = VALUE under [TABLE] in a TOML file,
# in place. Replaces the key if it already exists in that table, inserts it if
# the table exists but the key doesn't, or appends [TABLE] + key if the table is
# absent. VALUE is the raw RHS (caller quotes/brackets as needed). Table headers
# are matched by exact (trimmed) string, so [server.auth] and [server.auth.jwk]
# don't collide.
toml_set() {
    local file="$1" tbl="[$2]" key="$3" value="$4"
    awk -v tbl="$tbl" -v key="$key" -v val="$value" '
        function trim(s){ gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
        BEGIN { in_tbl=0; done=0; seen=0 }
        /^[ \t]*\[/ {
            if (in_tbl && !done) { print key " = " val; done=1 }
            in_tbl = (trim($0) == tbl); if (in_tbl) seen=1
            print; next
        }
        in_tbl && $0 ~ ("^[ \t]*" key "[ \t]*=") {
            if (!done) { print key " = " val; done=1 }
            next
        }
        { print }
        END {
            if (in_tbl && !done) print key " = " val
            else if (!seen) { print ""; print tbl; print key " = " val }
        }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# ──────────────────────────────────────────────────────────────────────────────
# Defaults / env-overridable knobs
# ──────────────────────────────────────────────────────────────────────────────
ASSUME_YES="${ASSUME_YES:-0}"
# --overwrite: regenerate config.toml even if it exists, rotate SESSION_SECRET,
# and force-set the lore-server auth keys in place. Default: preserve existing.
OVERWRITE="${OVERWRITE:-0}"
REPO_URL="${REPO_URL:-https://github.com/iniside/ArcLore.git}"
GO_MIN_MAJOR=1
GO_MIN_MINOR=24

# Install destinations — each service gets its own self-contained dir under /opt.
# arc-lore-auth keeps EVERYTHING (binary, config, SQLite DB, TLS cert/key, RSA
# signing key + issue secret) under OPT_AUTH_DIR, so the unit can run with the
# stricter ProtectHome profile and uninstall is a clean per-dir operation.
OPT_AUTH_DIR="/opt/arc-lore-auth"
OPT_AUTH_BIN="$OPT_AUTH_DIR/arc-lore-auth-linux-amd64"
OPT_AUTH_CONFIG="$OPT_AUTH_DIR/config.toml"
OPT_AUTH_DB="$OPT_AUTH_DIR/arc-lore.db"
OPT_AUTH_CERT="$OPT_AUTH_DIR/arc-lore-auth-tls.crt"
OPT_AUTH_TLS_KEY="$OPT_AUTH_DIR/arc-lore-auth-tls.key"
OPT_AUTH_KEY="$OPT_AUTH_DIR/arc-lore-auth.key"
OPT_AUTH_SECRET="$OPT_AUTH_DIR/arc-lore-auth.secret"
OPT_WEB_DIR="/opt/arcloreweb"
OPT_WEB_BIN="/opt/arcloreweb/arcloreweb"
# ArcLoreWeb dials arc-lore-auth's gRPC (:8443) over TLS for the token exchange;
# Go verifies against SSL_CERT_FILE. This bundle = system CAs + the auth cert.
WEB_CA_BUNDLE="/opt/arcloreweb/auth-ca-bundle.crt"
CA_BUNDLE_SRC="/etc/pki/tls/certs/ca-bundle.crt"
DEPLOY_DIR="/opt/arclore-deploy"
SYSTEMD_DIR="/etc/systemd/system"

# These may be pre-set via env for non-interactive installs.
LORE_HOST="${LORE_HOST:-}"
TOKEN_TTL="${TOKEN_TTL:-}"
ADMIN_SECRET="${ADMIN_SECRET:-}"
WEB_LISTEN="${WEB_LISTEN:-}"
SESSION_SECRET="${SESSION_SECRET:-}"
LORE_GRPC_PORT="${LORE_GRPC_PORT:-41337}"
LORE_HTTP_PORT="${LORE_HTTP_PORT:-41339}"

# ──────────────────────────────────────────────────────────────────────────────
# Arg parse
# ──────────────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: sudo ./install.sh [options]

  -y, --yes        Non-interactive: accept defaults for config prompts.
                   (Does NOT auto-restart Epic's loreserver.)
      --overwrite  Override existing configs instead of preserving them:
                   regenerate /opt/arc-lore-auth/config.toml from the prompts,
                   rotate SESSION_SECRET, and force-set the lore-server auth
                   keys (jwt_audience / jwk.endpoint / auth_url) in place even
                   if [server.auth] already exists. Default: keep existing.
      --repo URL   ArcLore git URL for the standalone-download path.
                   Default: $REPO_URL
  -h, --help       This help.

Config can also be supplied via environment:
  LORE_HOST, TOKEN_TTL, ADMIN_SECRET, WEB_LISTEN, SESSION_SECRET,
  LORE_GRPC_PORT (default 41337), LORE_HTTP_PORT (default 41339), REPO_URL.
EOF
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes) ASSUME_YES=1; shift ;;
        --overwrite) OVERWRITE=1; shift ;;
        --repo)   REPO_URL="${2:?--repo needs a URL}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown argument: $1 (try --help)" ;;
    esac
done

# ──────────────────────────────────────────────────────────────────────────────
# Pre-flight
# ──────────────────────────────────────────────────────────────────────────────
hdr "Pre-flight checks"

[[ "$(id -u)" -eq 0 ]] || die "Must run as root (use sudo)."

command -v git >/dev/null 2>&1 || die "git not found — install git and re-run."
command -v openssl >/dev/null 2>&1 || die "openssl not found — install openssl and re-run."
command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this installer targets systemd hosts."
command -v curl >/dev/null 2>&1 || die "curl not found — install curl and re-run."

if ! command -v go >/dev/null 2>&1; then
    err "Go toolchain not found."
    cat >&2 <<EOF

  Install Go >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR} (https://go.dev/dl/), e.g.:

    curl -fsSLO https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
    export PATH=\$PATH:/usr/local/go/bin

  Then re-run this installer. (We do NOT auto-install a toolchain.)
EOF
    exit 1
fi

# Verify Go >= min. `go version` prints e.g. "go version go1.24.3 linux/amd64".
GO_VER_RAW="$(go version | awk '{print $3}' | sed 's/^go//')"
GO_MAJOR="${GO_VER_RAW%%.*}"
GO_REST="${GO_VER_RAW#*.}"
GO_MINOR="${GO_REST%%.*}"
if (( GO_MAJOR < GO_MIN_MAJOR )) || { (( GO_MAJOR == GO_MIN_MAJOR )) && (( GO_MINOR < GO_MIN_MINOR )); }; then
    die "Go ${GO_VER_RAW} is too old; need >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR}."
fi
ok "go ${GO_VER_RAW}, git, openssl, curl, systemd present."

# ──────────────────────────────────────────────────────────────────────────────
# Source resolution: sibling dirs, else clone
# ──────────────────────────────────────────────────────────────────────────────
hdr "Resolving sources"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLONE_TMP=""            # set if we clone; cleaned up on exit
AUTH_SRC=""
WEB_SRC=""
DEPLOY_SRC="$SCRIPT_DIR"

cleanup() {
    if [[ -n "$CLONE_TMP" && -d "$CLONE_TMP" ]]; then
        log "Cleaning up build clone $CLONE_TMP"
        rm -rf "$CLONE_TMP"
    fi
}
trap cleanup EXIT

if [[ -d "$SCRIPT_DIR/../arc-lore-auth" && -d "$SCRIPT_DIR/../ArcLoreWeb" ]]; then
    AUTH_SRC="$(cd "$SCRIPT_DIR/../arc-lore-auth" && pwd)"
    WEB_SRC="$(cd "$SCRIPT_DIR/../ArcLoreWeb" && pwd)"
    ok "Building from sibling sources next to this script:"
    log "  arc-lore-auth: $AUTH_SRC"
    log "  ArcLoreWeb:    $WEB_SRC"
else
    log "Sibling sources not found — cloning $REPO_URL"
    CLONE_TMP="$(mktemp -d /tmp/arclore-build.XXXXXX)"
    git clone --depth 1 "$REPO_URL" "$CLONE_TMP/ArcLore"
    # Mirror layout: the ArcLore mirror has arc-lore-auth/ and ArcLoreWeb/ at root.
    if [[ -d "$CLONE_TMP/ArcLore/arc-lore-auth" && -d "$CLONE_TMP/ArcLore/ArcLoreWeb" ]]; then
        AUTH_SRC="$CLONE_TMP/ArcLore/arc-lore-auth"
        WEB_SRC="$CLONE_TMP/ArcLore/ArcLoreWeb"
        # Prefer the deploy assets from the clone if this script was downloaded alone.
        [[ -d "$CLONE_TMP/ArcLore/arclore-deploy" ]] && DEPLOY_SRC="$CLONE_TMP/ArcLore/arclore-deploy"
    else
        die "Cloned repo has no arc-lore-auth/ + ArcLoreWeb/ at root — wrong REPO_URL?"
    fi
    ok "Cloned into $CLONE_TMP/ArcLore"
fi

# The config template lives with the auth source. Both systemd units are
# generated inline below (for the self-contained /opt/arc-lore-auth layout), so
# the static deploy/arc-lore-auth.service is no longer needed at install time.
AUTH_CONFIG_TEMPLATE="$AUTH_SRC/config.toml"
WEB_UNIT_SRC="$DEPLOY_SRC/systemd/arcloreweb.service"
[[ -f "$AUTH_CONFIG_TEMPLATE" ]] || die "Missing $AUTH_CONFIG_TEMPLATE"
[[ -f "$WEB_UNIT_SRC" ]] || die "Missing $WEB_UNIT_SRC"

# ──────────────────────────────────────────────────────────────────────────────
# Interactive config
# ──────────────────────────────────────────────────────────────────────────────
hdr "Configuration"

DEFAULT_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "$DEFAULT_HOST" ]] || DEFAULT_HOST="$(hostname)"

ask LORE_HOST    "LORE_HOST (IP/hostname editors + lore-server use)" "$DEFAULT_HOST"
ask TOKEN_TTL    "Token TTL"                                          "168h"
ask WEB_LISTEN   "ArcLoreWeb listen address"                          ":41380"

[[ -n "$LORE_HOST" ]] || die "LORE_HOST cannot be empty."

if [[ -z "$ADMIN_SECRET" ]]; then
    ADMIN_SECRET="$(rand_hex 16)"   # 32 hex chars
    log "Generated random admin_secret (32 hex)."
fi
if [[ -z "$SESSION_SECRET" ]]; then
    # Reuse the SESSION_SECRET from an existing env-file so a re-run
    # doesn't invalidate live web sessions — unless --overwrite rotates it.
    EXISTING_SS=""
    if [[ "$OVERWRITE" != "1" && -f "/etc/arcloreweb/session-secret.env" ]]; then
        EXISTING_SS="$(sed -n 's/^SESSION_SECRET=//p' "/etc/arcloreweb/session-secret.env" 2>/dev/null | head -n1)"
    fi
    if [[ -n "$EXISTING_SS" ]]; then
        SESSION_SECRET="$EXISTING_SS"
        log "Reusing SESSION_SECRET from existing arcloreweb.service (--overwrite to rotate)."
    else
        SESSION_SECRET="$(rand_hex 32)" # 64 hex chars (>= 32 bytes)
        log "Generated random SESSION_SECRET."
    fi
fi

# Derived values.
WEB_BASE_URL="http://${LORE_HOST}:8080"
MGMT_API_ADDR="http://${LORE_HOST}:8080"
LORE_GRPC_ADDR="${LORE_HOST}:${LORE_GRPC_PORT}"
LORE_HTTP_ADDR="http://${LORE_HOST}:${LORE_HTTP_PORT}"

hdr "Summary"
cat <<EOF
  LORE_HOST          : $LORE_HOST
  tls_san / audience : $LORE_HOST
  token_ttl          : $TOKEN_TTL
  web_base_url       : $WEB_BASE_URL
  admin_secret       : ${ADMIN_SECRET:0:6}… (${#ADMIN_SECRET} chars)

  ArcLoreWeb:
    LISTEN_ADDR      : $WEB_LISTEN
    LORE_GRPC_ADDR   : $LORE_GRPC_ADDR
    LORE_HTTP_ADDR   : $LORE_HTTP_ADDR
    MGMT_API_ADDR    : $MGMT_API_ADDR
    SESSION_SECRET   : (random, ${#SESSION_SECRET} chars)

  Install paths:
    auth binary      : $OPT_AUTH_BIN
    auth config      : $OPT_AUTH_CONFIG
    auth db          : $OPT_AUTH_DB
    web binary       : $OPT_WEB_BIN
EOF

if ! confirm "Proceed with build + install?" "Y"; then
    die "Aborted by operator."
fi

# ──────────────────────────────────────────────────────────────────────────────
# Build
# ──────────────────────────────────────────────────────────────────────────────
hdr "Building arc-lore-auth"
(
    cd "$AUTH_SRC"
    log "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arc-lore-auth-linux-amd64 ."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arc-lore-auth-linux-amd64 .
)
[[ -f "$AUTH_SRC/arc-lore-auth-linux-amd64" ]] || die "arc-lore-auth build produced no binary."
ok "Built arc-lore-auth-linux-amd64"

hdr "Building ArcLoreWeb"
(
    cd "$WEB_SRC"
    log "go build -o arcloreweb ./cmd/arcloreweb"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arcloreweb ./cmd/arcloreweb
)
[[ -f "$WEB_SRC/arcloreweb" ]] || die "ArcLoreWeb build produced no binary."
ok "Built arcloreweb"

# ──────────────────────────────────────────────────────────────────────────────
# Install binaries + config
# ──────────────────────────────────────────────────────────────────────────────
hdr "Installing binaries"

# Create dedicated service accounts (idempotent).
if ! id arc-lore-auth >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin arc-lore-auth
    ok "Created system user arc-lore-auth"
else
    log "System user arc-lore-auth already exists — keeping."
fi
if ! id arcloreweb >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin arcloreweb
    ok "Created system user arcloreweb"
else
    log "System user arcloreweb already exists — keeping."
fi

install -d -m 0750 "$OPT_AUTH_DIR"
install -m 0750 "$AUTH_SRC/arc-lore-auth-linux-amd64" "$OPT_AUTH_BIN"
chown root:arc-lore-auth "$OPT_AUTH_BIN"
ok "Installed $OPT_AUTH_BIN (root:arc-lore-auth 0750)"

install -d -m 0755 "$OPT_WEB_DIR"
install -m 0750 "$WEB_SRC/arcloreweb" "$OPT_WEB_BIN"
chown root:arcloreweb "$OPT_WEB_BIN"
ok "Installed $OPT_WEB_BIN (root:arcloreweb 0750)"

install -d -m 0755 "$DEPLOY_DIR"

hdr "arc-lore-auth config ($OPT_AUTH_CONFIG)"

if [[ -f "$OPT_AUTH_CONFIG" && "$OVERWRITE" != "1" ]]; then
    ok "Existing config.toml found — KEEPING it (admin_secret + tuned values preserved)."
    log "Re-run with --overwrite to regenerate it from the prompts."
else
    if [[ -f "$OPT_AUTH_CONFIG" ]]; then
        cp -f "$OPT_AUTH_CONFIG" "${OPT_AUTH_CONFIG}.bak"
        warn "--overwrite: backed up existing $OPT_AUTH_CONFIG to ${OPT_AUTH_CONFIG}.bak"
    fi

    # Hash the admin_secret via the binary (argon2id PHC) so the plaintext never
    # lands in config.toml.  The binary is already installed above, so the hash
    # command is available here.  The plaintext is still shown in the summary.
    ADMIN_SECRET_HASH="$("$OPT_AUTH_BIN" hash-secret "$ADMIN_SECRET")"

    # Generate from the template, stripping any uncommented assignment of the keys
    # we own so our values win regardless of template drift, then append our block.
    STRIP_KEYS='^[[:space:]]*(tls_san|audience|web_base_url|admin_secret|db_path|token_ttl|web_listen_addr|grpc_listen_addr|key_path|secret_path|tls_cert_path|tls_key_path)[[:space:]]*='
    grep -vE "$STRIP_KEYS" "$AUTH_CONFIG_TEMPLATE" > "$OPT_AUTH_CONFIG"

    cat >> "$OPT_AUTH_CONFIG" <<EOF

# -- Generated by arclore-deploy/install.sh ($(date -u '+%Y-%m-%dT%H:%M:%SZ')) --
tls_san          = "${LORE_HOST}"
audience         = "${LORE_HOST}"
web_base_url     = "${WEB_BASE_URL}"
admin_secret     = "${ADMIN_SECRET_HASH}"
db_path          = "${OPT_AUTH_DB}"
token_ttl        = "${TOKEN_TTL}"
web_listen_addr  = "0.0.0.0:8080"
grpc_listen_addr = "0.0.0.0:8443"
# Pin all on-disk state under ${OPT_AUTH_DIR} (instead of root's home / cwd) so the
# unit can run with ProtectHome=true and the layout is fully self-contained.
key_path         = "${OPT_AUTH_KEY}"
secret_path      = "${OPT_AUTH_SECRET}"
tls_cert_path    = "${OPT_AUTH_CERT}"
tls_key_path     = "${OPT_AUTH_TLS_KEY}"
EOF
    chmod 0600 "$OPT_AUTH_CONFIG"   # holds admin_secret hash — keep it root-only.
    ok "Wrote $OPT_AUTH_CONFIG (mode 0600, admin_secret as argon2id hash)"
fi

# Give the auth service user ownership of its data dir so it can write
# the RSA signing key, TLS cert/key, and SQLite DB on first boot.
chown -R arc-lore-auth:arc-lore-auth "$OPT_AUTH_DIR"
# The binary lives inside this dir; keep it root-owned so the service user
# cannot rewrite its own executable (persistence hardening). Re-assert after
# the recursive chown above, which would otherwise hand it to the service user.
chown root:arc-lore-auth "$OPT_AUTH_BIN"
chmod 0750 "$OPT_AUTH_BIN"
ok "Set $OPT_AUTH_DIR ownership to arc-lore-auth:arc-lore-auth (binary stays root-owned)"

# ──────────────────────────────────────────────────────────────────────────────
# systemd units
# ──────────────────────────────────────────────────────────────────────────────
hdr "Installing systemd units"

# Generate arc-lore-auth.service for the self-contained /opt/arc-lore-auth layout.
# (The static deploy/arc-lore-auth.service is kept only as a manual reference —
# its paths target the older flat /opt layout.)
AUTH_UNIT_DST="$SYSTEMD_DIR/arc-lore-auth.service"
cat > "$AUTH_UNIT_DST" <<EOF
# arc-lore-auth.service — generated by arclore-deploy/install.sh
# $(date -u '+%Y-%m-%dT%H:%M:%SZ')

[Unit]
Description=arc-lore-auth — JWKS + gRPC auth (authz exchange + login) for self-hosted Lore
After=network-online.target
Wants=network-online.target
# Best-effort: be up before loreserver fetches JWKS at boot.
Before=loreserver.service

[Service]
Type=simple
User=arc-lore-auth
Group=arc-lore-auth
WorkingDirectory=${OPT_AUTH_DIR}
ExecStart=${OPT_AUTH_BIN} -config ${OPT_AUTH_CONFIG}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# Signing key + TLS cert/key + SQLite DB are pinned under ${OPT_AUTH_DIR}; the
# service user owns this dir so first-boot generation succeeds under strict mode.
ReadWritePaths=${OPT_AUTH_DIR}
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$AUTH_UNIT_DST"
ok "Installed arc-lore-auth.service (User=arc-lore-auth, ProtectSystem=strict, ReadWritePaths=${OPT_AUTH_DIR})"

# Write SESSION_SECRET to a root:arcloreweb-owned env-file (not inline in the unit).
install -d -m 0750 /etc/arcloreweb
printf 'SESSION_SECRET=%s\n' "$SESSION_SECRET" > /etc/arcloreweb/session-secret.env
chown root:arcloreweb /etc/arcloreweb/session-secret.env
chmod 0640 /etc/arcloreweb/session-secret.env
ok "Wrote /etc/arcloreweb/session-secret.env (root:arcloreweb 0640)"

# Write arcloreweb.service with real Environment= values substituted in.
WEB_UNIT_DST="$SYSTEMD_DIR/arcloreweb.service"
cat > "$WEB_UNIT_DST" <<EOF
# arcloreweb.service — generated by arclore-deploy/install.sh
# $(date -u '+%Y-%m-%dT%H:%M:%SZ')

[Unit]
Description=ArcLoreWeb — web frontend for self-hosted Lore (login + browse)
Documentation=file://${DEPLOY_DIR}/README.md
After=network-online.target arc-lore-auth.service
Wants=network-online.target

[Service]
Type=simple
User=arcloreweb
Group=arcloreweb
WorkingDirectory=${OPT_WEB_DIR}
ExecStart=${OPT_WEB_BIN}
Restart=on-failure
RestartSec=3

Environment=LISTEN_ADDR=${WEB_LISTEN}
Environment=LORE_GRPC_ADDR=${LORE_GRPC_ADDR}
Environment=LORE_HTTP_ADDR=${LORE_HTTP_ADDR}
Environment=MGMT_API_ADDR=${MGMT_API_ADDR}
Environment=LORE_AUTH_DISABLED=false
# Trust arc-lore-auth's self-signed gRPC cert for the token-exchange TLS call.
Environment=SSL_CERT_FILE=${WEB_CA_BUNDLE}
# SESSION_SECRET is loaded from a restricted env-file (root:arcloreweb 0640)
# so it never appears in the unit or journald output.
EnvironmentFile=/etc/arcloreweb/session-secret.env

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# ArcLoreWeb is stateless — no runtime writes under any protected path.
# (All logging goes to journald; no on-disk state beyond the binary dir.)
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$WEB_UNIT_DST"
ok "Installed arcloreweb.service (User=arcloreweb, ProtectSystem=strict, SESSION_SECRET via EnvironmentFile)"

log "systemctl daemon-reload"
systemctl daemon-reload

# Start arc-lore-auth FIRST and wait for it (it generates the TLS cert + key).
# Use restart (not `enable --now`): `start`/`--now` is a no-op on an already
# running unit, so an in-place upgrade over an existing arc-lore-auth would keep
# the OLD binary running. restart guarantees the new binary is loaded.
hdr "Starting arc-lore-auth"
systemctl enable arc-lore-auth.service
systemctl restart arc-lore-auth.service

log "Waiting for arc-lore-auth to answer on http://127.0.0.1:8080/healthz …"
AUTH_UP=0
for _i in $(seq 1 30); do
    if curl -sf -o /dev/null "http://127.0.0.1:8080/healthz"; then
        AUTH_UP=1; break
    fi
    sleep 1
done
if [[ "$AUTH_UP" != "1" ]]; then
    err "arc-lore-auth did not become healthy in 30s."
    err "Check: journalctl -u arc-lore-auth -n 50"
    die "Aborting before starting ArcLoreWeb."
fi
ok "arc-lore-auth is healthy."

# ArcLoreWeb dials arc-lore-auth's gRPC (:8443) over TLS for the token exchange.
# Its Go client verifies against SSL_CERT_FILE — build a bundle of the system CAs
# plus arc-lore-auth's (now-generated) self-signed cert. Without this the exchange
# fails with "x509: certificate signed by unknown authority".
hdr "ArcLoreWeb auth trust bundle"
if [[ -f "$OPT_AUTH_CERT" && -f "$CA_BUNDLE_SRC" ]]; then
    cat "$CA_BUNDLE_SRC" "$OPT_AUTH_CERT" > "$WEB_CA_BUNDLE"
    chown root:arcloreweb "$WEB_CA_BUNDLE"
    chmod 0640 "$WEB_CA_BUNDLE"
    ok "Wrote $WEB_CA_BUNDLE (root:arcloreweb 0640 — system CAs + auth cert)."
else
    warn "Could not build $WEB_CA_BUNDLE (missing $OPT_AUTH_CERT or $CA_BUNDLE_SRC)."
    warn "ArcLoreWeb's token exchange will fail TLS until this bundle exists."
fi

hdr "Starting ArcLoreWeb"
systemctl enable arcloreweb.service
systemctl restart arcloreweb.service
# Best-effort liveness check on the web listener.
WEB_PORT="${WEB_LISTEN##*:}"
if [[ -n "$WEB_PORT" ]]; then
    for _i in $(seq 1 15); do
        if curl -sf -o /dev/null "http://127.0.0.1:${WEB_PORT}/" 2>/dev/null; then
            ok "ArcLoreWeb is answering on :${WEB_PORT}"; break
        fi
        sleep 1
    done
fi

# ──────────────────────────────────────────────────────────────────────────────
# Cert export
# ──────────────────────────────────────────────────────────────────────────────
hdr "Exporting TLS certificate"

CERT_DST="$DEPLOY_DIR/arc-lore-auth-tls.crt"
CERT_SHA1=""
if [[ -f "$OPT_AUTH_CERT" ]]; then
    install -m 0644 "$OPT_AUTH_CERT" "$CERT_DST"
    ok "Copied cert to $CERT_DST"
    CERT_SHA1="$(openssl x509 -in "$CERT_DST" -noout -fingerprint -sha1 2>/dev/null | sed 's/.*=//')"
    log "SHA1 fingerprint: ${CERT_SHA1:-<unavailable>}"
else
    warn "Expected cert $OPT_AUTH_CERT not found yet."
    warn "arc-lore-auth generates it on first start with both cert+key absent."
    warn "Re-check: ls -l $OPT_AUTH_CERT ; then copy it to $CERT_DST manually."
fi

# ──────────────────────────────────────────────────────────────────────────────
# OPTIONAL: lore-server integration (edits Epic's service — confirm each step)
# ──────────────────────────────────────────────────────────────────────────────
LORESERVER_CONFIG_DIR="/opt/loreserver/config"
LORESERVER_BUNDLE="/opt/loreserver/auth-ca-bundle.crt"
LORESERVER_DROPIN_DIR="$SYSTEMD_DIR/loreserver.service.d"
LORESERVER_DROPIN="$LORESERVER_DROPIN_DIR/ssl-cert-file.conf"
# CA_BUNDLE_SRC is defined once in the path-vars block near the top.

# The exact config block we recommend (printed regardless of auto-apply).
read -r -d '' LORESERVER_BLOCK <<EOF || true
[server.auth]
jwt_audience = ["${LORE_HOST}"]

[server.auth.jwk]
endpoint = "${WEB_BASE_URL}/jwks.json"

[environment.endpoint]
auth_url = "https://${LORE_HOST}:8443"
EOF

LORE_CFG_FILE=""
if compgen -G "$LORESERVER_CONFIG_DIR/*.toml" >/dev/null 2>&1; then
    LORE_CFG_FILE="$(ls -1 "$LORESERVER_CONFIG_DIR"/*.toml | head -n1)"
fi

if [[ -n "$LORE_CFG_FILE" ]]; then
    hdr "Wiring into lore-server"
    log  "Detected lore-server config: $LORE_CFG_FILE"
    warn "lore-server must trust arc-lore-auth's (self-signed, possibly NEW) cert and"
    warn "re-fetch its JWKS. This rebuilds the trust bundle and RESTARTS loreserver."
    warn "Required whenever arc-lore-auth's cert/signing-key are (re)generated."

    # Interactive: default Yes (this is the step that makes repo ops work). But
    # under -y (fully unattended) we still do NOT auto-restart Epic's loreserver —
    # surface it so the operator runs it deliberately.
    _do_lore=1
    if [[ "$ASSUME_YES" == "1" ]]; then
        warn "-y given: NOT auto-editing/restarting Epic's loreserver."
        _do_lore=0
    elif ! confirm "Trust arc-lore-auth in lore-server and restart loreserver now?" "Y"; then
        _do_lore=0
    fi
    if [[ "$_do_lore" == "1" ]]; then
        # 1) Ensure the [server.auth] config block exists — add ONLY if genuinely
        #    absent (detect the real table header, not just our marker), so a
        #    pre-configured lore-server is left untouched (no duplicate tables).
        if grep -qE '^[[:space:]]*\[server\.auth\]' "$LORE_CFG_FILE"; then
            if [[ "$OVERWRITE" == "1" ]]; then
                cp -f "$LORE_CFG_FILE" "${LORE_CFG_FILE}.bak"
                warn "--overwrite: backed up $LORE_CFG_FILE; force-setting auth keys in place."
                toml_set "$LORE_CFG_FILE" "server.auth"          "jwt_audience" "[\"${LORE_HOST}\"]"
                toml_set "$LORE_CFG_FILE" "server.auth.jwk"      "endpoint"     "\"${WEB_BASE_URL}/jwks.json\""
                toml_set "$LORE_CFG_FILE" "environment.endpoint" "auth_url"     "\"https://${LORE_HOST}:8443\""
                ok "Force-set jwt_audience / jwk.endpoint / auth_url in $LORE_CFG_FILE."
            else
                ok "lore-server [server.auth] already present — leaving config as-is (--overwrite to force-set)."
            fi
        else
            cp -f "$LORE_CFG_FILE" "${LORE_CFG_FILE}.bak"
            warn "Backed up to ${LORE_CFG_FILE}.bak"
            {
                printf '\n# -- arclore-deploy: auth block (%s) --\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
                printf '%s\n' "$LORESERVER_BLOCK"
            } >> "$LORE_CFG_FILE"
            ok "Added [server.auth] block to $LORE_CFG_FILE"
        fi

        # 2) Rebuild the SSL_CERT_FILE trust bundle (system CAs + the auth cert).
        #    lore-server's rustls uses the native root store, which excludes a
        #    CA:FALSE self-signed cert; this bundle pins it. Idempotent — always
        #    reflects the CURRENT cert, so a regenerated cert is picked up.
        if [[ ! -f "$CERT_DST" ]]; then
            warn "Cert $CERT_DST not present — cannot build trust bundle."
            warn "Re-run after arc-lore-auth has generated /opt/arc-lore-auth-tls.crt."
        elif [[ ! -f "$CA_BUNDLE_SRC" ]]; then
            warn "System CA bundle $CA_BUNDLE_SRC not found (non-RHEL layout?)."
            warn "Build manually: cat <base-ca-bundle> $CERT_DST > $LORESERVER_BUNDLE"
        else
            cat "$CA_BUNDLE_SRC" "$CERT_DST" > "$LORESERVER_BUNDLE"
            chmod 0644 "$LORESERVER_BUNDLE"
            ok "Wrote trust bundle $LORESERVER_BUNDLE (system CAs + auth cert)"
            install -d -m 0755 "$LORESERVER_DROPIN_DIR"
            cat > "$LORESERVER_DROPIN" <<EOF
# arclore-deploy: trust arc-lore-auth self-signed cert for lore-server outbound TLS.
[Service]
Environment=SSL_CERT_FILE=${LORESERVER_BUNDLE}
EOF
            chmod 0644 "$LORESERVER_DROPIN"
            ok "Wrote drop-in $LORESERVER_DROPIN"
        fi

        # 3) Reload + restart loreserver — loads the new cert trust AND re-fetches
        #    the JWKS (lore-server fetches JWKS only at startup; its lazy refetch
        #    does not pick up a new kid, so a restart is mandatory after a key change).
        systemctl daemon-reload
        log "Restarting loreserver (new cert trust + JWKS)…"
        if systemctl restart loreserver 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet loreserver; then
                ok "loreserver restarted and active."
            else
                warn "loreserver is NOT active after restart — check: journalctl -u loreserver -n 50"
            fi
        else
            warn "Could not restart loreserver (unit named differently?)."
            warn "Restart manually: sudo systemctl daemon-reload && sudo systemctl restart loreserver"
        fi
    else
        warn "Skipped lore-server wiring. Repo ops will FAIL until lore-server trusts"
        warn "the auth cert and re-fetches JWKS. Apply the block + bundle below manually,"
        warn "then: sudo systemctl daemon-reload && sudo systemctl restart loreserver"
    fi
else
    hdr "lore-server integration"
    log "No $LORESERVER_CONFIG_DIR/*.toml found — skipping auto-integration."
    log "Apply the config block below to your lore-server manually."
fi

# ──────────────────────────────────────────────────────────────────────────────
# Final summary
# ──────────────────────────────────────────────────────────────────────────────
hdr "Done"
cat <<EOF
${C_OK}ArcLore stack installed.${C_RESET}

1) Create the first admin user:
     Open  ${C_BOLD}http://${LORE_HOST}:${WEB_LISTEN##*:}${C_RESET}  → "Sign in" / first-run setup
     (the first registered user becomes admin), or:
       curl -sf -X POST ${MGMT_API_ADDR}/api/setup   # see ArcLoreWeb /setup

2) Trust the TLS cert on each Windows editor host:
     cert : ${CERT_DST}
     SHA1 : ${CERT_SHA1:-<run: openssl x509 -in $CERT_DST -noout -fingerprint -sha1>}
     On the editor host (elevated PowerShell or cmd):
       certutil -addstore -f Root arc-lore-auth-tls.crt
     (or use arclore-deploy/install-windows.ps1 -CertPath .\\arc-lore-auth-tls.crt)
     The cert SAN is "${LORE_HOST}" — it MUST match the auth_url host the editor dials.

3) Exposing ArcLoreWeb beyond the LAN? See README.md "HTTPS / reverse proxy" for
     nginx/Caddy snippets and the SESSION_COOKIE_SECURE / CSRF_TRUSTED_ORIGINS /
     TRUST_FORWARDED_FOR knobs to set in arcloreweb.service.

4) lore-server config block (apply if not auto-applied above):
${LORESERVER_BLOCK}
   Plus, for lore-server's OWN outbound TLS to the auth service:
     cat ${CA_BUNDLE_SRC} ${CERT_DST} > ${LORESERVER_BUNDLE}
     drop-in ${LORESERVER_DROPIN}:
       [Service]
       Environment=SSL_CERT_FILE=${LORESERVER_BUNDLE}
     then: sudo systemctl daemon-reload && sudo systemctl restart loreserver

Logs:
   journalctl -u arc-lore-auth -f
   journalctl -u arcloreweb -f
EOF
