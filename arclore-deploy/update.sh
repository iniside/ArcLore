#!/usr/bin/env bash
#
# update.sh — in-place binary update for an already-installed ArcLore stack.
#
# Rebuilds OUR two Go services and swaps the running binaries, NOTHING else:
#   * arc-lore-auth  — /opt/arc-lore-auth/arc-lore-auth-linux-amd64
#   * ArcLoreWeb     — /opt/arcloreweb/arcloreweb
#
# Deliberately does NOT touch: config.toml, the SQLite DB, the RSA signing key
# (so the JWKS `kid` is UNCHANGED → existing tokens keep validating, Windows
# editor hosts need NO cert re-trust, and lore-server needs NO restart), the TLS
# cert/key, the systemd units, or Epic's lore-server. For first-time setup, or to
# change config / regenerate certs / re-wire lore-server, use install.sh instead.
#
# Source resolution mirrors install.sh: build from sibling arc-lore-auth/ +
# ArcLoreWeb/ dirs next to this script if present, else clone the ArcLore mirror.
#
# Workflow:
#   cd ArcLore && git pull && sudo ./arclore-deploy/update.sh
# OR (standalone, from a checkout that is a git repo):
#   sudo ./arclore-deploy/update.sh --pull          # git pull the source first
#
# Run as root. Strict mode.

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Logging (identical palette to install.sh)
# ──────────────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_OK=$'\033[32m'
    C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_BOLD=''
fi
log()  { printf '%s[*]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_OK"   "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_ERR"  "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }
hdr()  { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_RESET"; }

# ──────────────────────────────────────────────────────────────────────────────
# Paths (mirror install.sh — must match where install.sh put things)
# ──────────────────────────────────────────────────────────────────────────────
OPT_AUTH_DIR="/opt/arc-lore-auth"
OPT_AUTH_BIN="$OPT_AUTH_DIR/arc-lore-auth-linux-amd64"
OPT_WEB_DIR="/opt/arcloreweb"
OPT_WEB_BIN="$OPT_WEB_DIR/arcloreweb"
SYSTEMD_DIR="/etc/systemd/system"

REPO_URL="${REPO_URL:-https://github.com/iniside/ArcLore.git}"
GO_MIN_MAJOR=1
GO_MIN_MINOR=24

# ──────────────────────────────────────────────────────────────────────────────
# Arg parse
# ──────────────────────────────────────────────────────────────────────────────
DO_AUTH=1
DO_WEB=1
PULL=0
usage() {
    cat <<EOF
Usage: sudo ./update.sh [options]

  --auth-only   Rebuild + restart only arc-lore-auth.
  --web-only    Rebuild + restart only ArcLoreWeb.
  --pull        If the source dir is a git checkout, 'git pull' before building.
  --repo URL    ArcLore git URL for the clone fallback. Default: $REPO_URL
  -h, --help    This help.

Updates binaries in place and restarts services. Preserves config, DB, signing
key (stable kid), TLS cert, systemd units, and lore-server. For first install or
config/cert changes, use install.sh.
EOF
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auth-only) DO_WEB=0; shift ;;
        --web-only)  DO_AUTH=0; shift ;;
        --pull)      PULL=1; shift ;;
        --repo)      REPO_URL="${2:?--repo needs a URL}"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *) die "Unknown argument: $1 (try --help)" ;;
    esac
done
[[ "$DO_AUTH" == "1" || "$DO_WEB" == "1" ]] || die "--auth-only and --web-only are mutually exclusive."

# ──────────────────────────────────────────────────────────────────────────────
# Pre-flight
# ──────────────────────────────────────────────────────────────────────────────
hdr "Pre-flight checks"

[[ "$(id -u)" -eq 0 ]] || die "Must run as root (use sudo)."
command -v git >/dev/null 2>&1 || die "git not found."
command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this targets systemd hosts."
command -v curl >/dev/null 2>&1 || die "curl not found."
command -v go  >/dev/null 2>&1 || die "Go toolchain not found — install Go >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR}."

# Verify Go >= min (same check as install.sh).
GO_VER_RAW="$(go version | awk '{print $3}' | sed 's/^go//')"
GO_MAJOR="${GO_VER_RAW%%.*}"
GO_REST="${GO_VER_RAW#*.}"
GO_MINOR="${GO_REST%%.*}"
if (( GO_MAJOR < GO_MIN_MAJOR )) || { (( GO_MAJOR == GO_MIN_MAJOR )) && (( GO_MINOR < GO_MIN_MINOR )); }; then
    die "Go ${GO_VER_RAW} is too old; need >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR}."
fi

# The stack must already be installed — this is an UPDATE, not an install.
if [[ "$DO_AUTH" == "1" ]]; then
    systemctl list-unit-files arc-lore-auth.service >/dev/null 2>&1 \
        && [[ -f "$SYSTEMD_DIR/arc-lore-auth.service" ]] \
        || die "arc-lore-auth.service not installed — run install.sh first."
    [[ -d "$OPT_AUTH_DIR" ]] || die "$OPT_AUTH_DIR missing — run install.sh first."
fi
if [[ "$DO_WEB" == "1" ]]; then
    systemctl list-unit-files arcloreweb.service >/dev/null 2>&1 \
        && [[ -f "$SYSTEMD_DIR/arcloreweb.service" ]] \
        || die "arcloreweb.service not installed — run install.sh first."
    [[ -d "$OPT_WEB_DIR" ]] || die "$OPT_WEB_DIR missing — run install.sh first."
fi
ok "go ${GO_VER_RAW}, git, systemd present; target service(s) installed."

# ──────────────────────────────────────────────────────────────────────────────
# Source resolution: sibling dirs, else clone (mirrors install.sh)
# ──────────────────────────────────────────────────────────────────────────────
hdr "Resolving sources"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLONE_TMP=""
AUTH_SRC=""
WEB_SRC=""

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

    # --pull: refresh the checkout before building. The two services may live in
    # one repo (the mirror, with a single .git at the parent) or two — pull each
    # git work-tree we find, deduped by toplevel.
    if [[ "$PULL" == "1" ]]; then
        PULLED=""
        for d in "$AUTH_SRC" "$WEB_SRC" "$SCRIPT_DIR"; do
            if top="$(git -C "$d" rev-parse --show-toplevel 2>/dev/null)"; then
                case " $PULLED " in
                    *" $top "*) : ;;  # already pulled this work-tree
                    *)
                        log "git -C $top pull --ff-only"
                        git -C "$top" pull --ff-only || warn "git pull failed in $top — building current checkout."
                        PULLED="$PULLED $top"
                        ;;
                esac
            fi
        done
        [[ -n "$PULLED" ]] || warn "--pull: no git work-tree found around the sources — nothing to pull."
    fi
else
    [[ "$PULL" == "1" ]] && warn "--pull ignored: no sibling sources; cloning a fresh copy instead."
    log "Sibling sources not found — cloning $REPO_URL"
    CLONE_TMP="$(mktemp -d /tmp/arclore-update.XXXXXX)"
    git clone --depth 1 "$REPO_URL" "$CLONE_TMP/ArcLore"
    if [[ -d "$CLONE_TMP/ArcLore/arc-lore-auth" && -d "$CLONE_TMP/ArcLore/ArcLoreWeb" ]]; then
        AUTH_SRC="$CLONE_TMP/ArcLore/arc-lore-auth"
        WEB_SRC="$CLONE_TMP/ArcLore/ArcLoreWeb"
    else
        die "Cloned repo has no arc-lore-auth/ + ArcLoreWeb/ at root — wrong REPO_URL?"
    fi
    ok "Cloned into $CLONE_TMP/ArcLore"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Build (only the requested service(s); same flags as install.sh)
# ──────────────────────────────────────────────────────────────────────────────
if [[ "$DO_AUTH" == "1" ]]; then
    hdr "Building arc-lore-auth"
    (
        cd "$AUTH_SRC"
        log "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arc-lore-auth-linux-amd64 ."
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arc-lore-auth-linux-amd64 .
    )
    [[ -f "$AUTH_SRC/arc-lore-auth-linux-amd64" ]] || die "arc-lore-auth build produced no binary."
    ok "Built arc-lore-auth-linux-amd64"
fi
if [[ "$DO_WEB" == "1" ]]; then
    hdr "Building ArcLoreWeb"
    (
        cd "$WEB_SRC"
        log "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arcloreweb ./cmd/arcloreweb"
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arcloreweb ./cmd/arcloreweb
    )
    [[ -f "$WEB_SRC/arcloreweb" ]] || die "ArcLoreWeb build produced no binary."
    ok "Built arcloreweb"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Swap binaries + restart. `install` over a running binary is safe on Linux (the
# running process keeps the old inode until restart). restart (not start) is
# mandatory so the new binary is actually loaded.
# ──────────────────────────────────────────────────────────────────────────────
if [[ "$DO_AUTH" == "1" ]]; then
    hdr "Updating arc-lore-auth"
    install -m 0750 "$AUTH_SRC/arc-lore-auth-linux-amd64" "$OPT_AUTH_BIN"
    chown root:arc-lore-auth "$OPT_AUTH_BIN"
    ok "Installed $OPT_AUTH_BIN (root:arc-lore-auth 0750)"
    log "systemctl restart arc-lore-auth.service"
    systemctl restart arc-lore-auth.service

    log "Waiting for arc-lore-auth to answer on http://127.0.0.1:8080/healthz …"
    AUTH_UP=0
    for _i in $(seq 1 30); do
        if curl -sf -o /dev/null "http://127.0.0.1:8080/healthz"; then
            AUTH_UP=1; break
        fi
        sleep 1
    done
    if [[ "$AUTH_UP" == "1" ]]; then
        ok "arc-lore-auth is healthy."
    else
        err "arc-lore-auth did not become healthy in 30s."
        die "Check: journalctl -u arc-lore-auth -n 50"
    fi
fi

if [[ "$DO_WEB" == "1" ]]; then
    hdr "Updating ArcLoreWeb"
    install -m 0750 "$WEB_SRC/arcloreweb" "$OPT_WEB_BIN"
    chown root:arcloreweb "$OPT_WEB_BIN"
    ok "Installed $OPT_WEB_BIN (root:arcloreweb 0750)"
    log "systemctl restart arcloreweb.service"
    systemctl restart arcloreweb.service

    # Best-effort liveness on the configured listen port (read from the unit).
    WEB_LISTEN="$(sed -n 's/^Environment=LISTEN_ADDR=\(.*\)$/\1/p' "$SYSTEMD_DIR/arcloreweb.service" | head -n1)"
    WEB_PORT="${WEB_LISTEN##*:}"
    if [[ -n "$WEB_PORT" ]]; then
        WEB_UP=0
        for _i in $(seq 1 15); do
            if curl -sf -o /dev/null "http://127.0.0.1:${WEB_PORT}/" 2>/dev/null; then
                WEB_UP=1; break
            fi
            sleep 1
        done
        if [[ "$WEB_UP" == "1" ]]; then
            ok "ArcLoreWeb is answering on :${WEB_PORT}"
        else
            warn "ArcLoreWeb not answering on :${WEB_PORT} yet — check: journalctl -u arcloreweb -n 50"
        fi
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Done
# ──────────────────────────────────────────────────────────────────────────────
hdr "Done"
cat <<EOF
${C_OK}Binaries updated and service(s) restarted.${C_RESET}

Preserved (unchanged): config.toml, SQLite DB, RSA signing key (kid stable),
TLS cert/key, systemd units, lore-server. No Windows cert re-trust and no
loreserver restart are needed — the signing key did not change.

${C_WARN}If this update changed what goes INTO a token${C_RESET} (e.g. the admin permission
set), existing tokens still carry the OLD claims. Affected users must re-login
to mint a fresh token:
   * Web : log out, then log back in.
   * CLI : lore login   (after 'lore auth logout --auth-url https://<host>:8443'
           if a non-expired token is cached).

Logs:
   journalctl -u arc-lore-auth -f
   journalctl -u arcloreweb -f
EOF
