#!/usr/bin/env bash
#
# uninstall.sh — remove the ArcLore control plane installed by install.sh.
#
# Removes OUR two services (arc-lore-auth, ArcLoreWeb). Does NOT touch Epic's
# lore-server beyond optionally reverting the integration edits install.sh made.
#
# By default it KEEPS data (SQLite DB, RSA signing key, issue secret, TLS cert/key)
# so a reinstall preserves users and does not invalidate issued tokens. Pass
# --purge (or answer "yes" to the wipe prompt) to also delete the data.

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
log()  { printf '%s[*]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_OK"   "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_ERR"  "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }
hdr()  { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_RESET"; }

confirm() {
    local prompt="$1" def="${2:-N}" reply hint="[y/N]"
    [[ "$def" == "Y" ]] && hint="[Y/n]"
    read -r -p "$prompt $hint " reply || true
    reply="${reply:-$def}"
    [[ "$reply" =~ ^[Yy] ]]
}

# ──────────────────────────────────────────────────────────────────────────────
# Paths (mirror install.sh)
# ──────────────────────────────────────────────────────────────────────────────
OPT_AUTH_DIR="/opt/arc-lore-auth"
OPT_AUTH_BIN="$OPT_AUTH_DIR/arc-lore-auth-linux-amd64"
OPT_AUTH_CONFIG="$OPT_AUTH_DIR/config.toml"
OPT_AUTH_DB="$OPT_AUTH_DIR/arc-lore.db"
OPT_AUTH_CERT="$OPT_AUTH_DIR/arc-lore-auth-tls.crt"
OPT_AUTH_TLS_KEY="$OPT_AUTH_DIR/arc-lore-auth-tls.key"
OPT_AUTH_RSA_KEY="$OPT_AUTH_DIR/arc-lore-auth.key"
OPT_AUTH_SECRET="$OPT_AUTH_DIR/arc-lore-auth.secret"
OPT_WEB_DIR="/opt/arcloreweb"
# Legacy flat /opt layout (pre-subfolder installs) — cleaned up too if present.
LEGACY_AUTH_BIN="/opt/arc-lore-auth-linux-amd64"
LEGACY_AUTH_CONFIG="/opt/config.toml"
LEGACY_RSA_DIR="/root/.arc-lore-auth"
DEPLOY_DIR="/opt/arclore-deploy"
SYSTEMD_DIR="/etc/systemd/system"

LORESERVER_BUNDLE="/opt/loreserver/auth-ca-bundle.crt"
LORESERVER_DROPIN_DIR="$SYSTEMD_DIR/loreserver.service.d"
LORESERVER_DROPIN="$LORESERVER_DROPIN_DIR/ssl-cert-file.conf"
LORESERVER_CONFIG_DIR="/opt/loreserver/config"

PURGE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) PURGE=1; shift ;;
        -h|--help)
            echo "Usage: sudo ./uninstall.sh [--purge]"
            echo "  --purge   Also delete DB, RSA key, issue secret, TLS cert/key, and session-secret."
            exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ──────────────────────────────────────────────────────────────────────────────
# Confirm
# ──────────────────────────────────────────────────────────────────────────────
hdr "ArcLore uninstall"
[[ "$(id -u)" -eq 0 ]] || die "Must run as root (use sudo)."

warn "This stops and removes arc-lore-auth + ArcLoreWeb (services + binaries + config)."
read -r -p "Type 'yes' to continue: " __c || true
[[ "$__c" == "yes" ]] || die "Aborted (must type 'yes')."

REMOVED=()
KEPT=()

# ──────────────────────────────────────────────────────────────────────────────
# Stop + remove services
# ──────────────────────────────────────────────────────────────────────────────
hdr "Stopping services"
for svc in arcloreweb arc-lore-auth; do
    if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 \
       && systemctl cat "${svc}.service" >/dev/null 2>&1; then
        systemctl disable --now "${svc}.service" 2>/dev/null || true
        ok "Stopped + disabled ${svc}.service"
    fi
    if [[ -f "$SYSTEMD_DIR/${svc}.service" ]]; then
        rm -f "$SYSTEMD_DIR/${svc}.service"
        REMOVED+=("$SYSTEMD_DIR/${svc}.service")
    fi
    # Drop-in dir (e.g. arcloreweb's SSL_CERT_FILE override).
    if [[ -d "$SYSTEMD_DIR/${svc}.service.d" ]]; then
        rm -rf "$SYSTEMD_DIR/${svc}.service.d"
        REMOVED+=("$SYSTEMD_DIR/${svc}.service.d/")
    fi
done
systemctl daemon-reload
ok "daemon-reload done."

# ──────────────────────────────────────────────────────────────────────────────
# Remove binaries + config
# ──────────────────────────────────────────────────────────────────────────────
hdr "Removing binaries + config"
for f in "$OPT_AUTH_BIN" "$OPT_AUTH_CONFIG" "${OPT_AUTH_CONFIG}.bak" \
         "$LEGACY_AUTH_BIN" "$LEGACY_AUTH_CONFIG" "${LEGACY_AUTH_CONFIG}.bak"; do
    if [[ -e "$f" ]]; then rm -f "$f"; REMOVED+=("$f"); fi
done
if [[ -d "$OPT_WEB_DIR" ]]; then
    [[ "$OPT_WEB_DIR" =~ ^/opt/ ]] || { err "Refusing rm -rf $OPT_WEB_DIR (path does not start with /opt/)"; exit 1; }
    rm -rf "$OPT_WEB_DIR"; REMOVED+=("$OPT_WEB_DIR/")
fi

# ──────────────────────────────────────────────────────────────────────────────
# Data prompt (default KEEP)
# ──────────────────────────────────────────────────────────────────────────────
hdr "Data (DB / keys / cert)"
DATA_PATHS=("$OPT_AUTH_DB" "$OPT_AUTH_RSA_KEY" "$OPT_AUTH_SECRET" "$OPT_AUTH_CERT" "$OPT_AUTH_TLS_KEY" "$LEGACY_RSA_DIR" "/etc/arcloreweb/session-secret.env")

WIPE=0
if [[ "$PURGE" == "1" ]]; then
    WIPE=1
    log "--purge given."
else
    warn "Keeping data lets a reinstall preserve users + signing key (tokens stay valid)."
    warn "Wiping removes: ${DATA_PATHS[*]}"
    if confirm "Wipe ALL data (DB, RSA signing key, issue secret, TLS cert/key, session-secret)?" "N"; then
        read -r -p "This is destructive. Type 'yes' to wipe: " __w || true
        [[ "$__w" == "yes" ]] && WIPE=1
    fi
fi

if [[ "$WIPE" == "1" ]]; then
    for p in "${DATA_PATHS[@]}"; do
        if [[ -e "$p" ]]; then rm -rf "$p"; REMOVED+=("$p"); fi
    done
    # Remove the session-secret dir if now empty.
    if [[ -d "/etc/arcloreweb" ]] && [[ -z "$(ls -A "/etc/arcloreweb" 2>/dev/null)" ]]; then
        rmdir "/etc/arcloreweb" 2>/dev/null || true
        REMOVED+=("/etc/arcloreweb/")
    fi
    # Drop the now-empty app dir on a full purge.
    if [[ -d "$OPT_AUTH_DIR" ]]; then
        [[ "$OPT_AUTH_DIR" =~ ^/opt/ ]] || { err "Refusing rm -rf $OPT_AUTH_DIR (path does not start with /opt/)"; exit 1; }
        rmdir "$OPT_AUTH_DIR" 2>/dev/null && REMOVED+=("$OPT_AUTH_DIR/") || true
    fi
    ok "Data wiped."
else
    for p in "${DATA_PATHS[@]}"; do
        [[ -e "$p" ]] && KEPT+=("$p")
    done
    log "Data KEPT."
fi

# ──────────────────────────────────────────────────────────────────────────────
# Optional: revert lore-server integration (default No)
# ──────────────────────────────────────────────────────────────────────────────
hdr "Optional: revert lore-server integration"
if [[ -e "$LORESERVER_DROPIN" || -e "$LORESERVER_BUNDLE" ]] \
   || compgen -G "$LORESERVER_CONFIG_DIR/*.toml.bak" >/dev/null 2>&1; then
    warn "This reverts edits install.sh made to Epic's lore-server. Default No."
    if confirm "Revert lore-server integration (remove SSL_CERT_FILE drop-in + bundle, restore *.toml.bak)?" "N"; then
        if [[ -f "$LORESERVER_DROPIN" ]]; then rm -f "$LORESERVER_DROPIN"; REMOVED+=("$LORESERVER_DROPIN"); fi
        # Remove the drop-in dir only if now empty.
        if [[ -d "$LORESERVER_DROPIN_DIR" ]] && [[ -z "$(ls -A "$LORESERVER_DROPIN_DIR" 2>/dev/null)" ]]; then
            rmdir "$LORESERVER_DROPIN_DIR" 2>/dev/null || true
        fi
        if [[ -f "$LORESERVER_BUNDLE" ]]; then rm -f "$LORESERVER_BUNDLE"; REMOVED+=("$LORESERVER_BUNDLE"); fi

        # Restore any *.toml.bak install.sh left behind.
        if compgen -G "$LORESERVER_CONFIG_DIR/*.toml.bak" >/dev/null 2>&1; then
            for bak in "$LORESERVER_CONFIG_DIR"/*.toml.bak; do
                orig="${bak%.bak}"
                if confirm "Restore $orig from $bak?" "N"; then
                    cp -f "$bak" "$orig"
                    ok "Restored $orig"
                fi
            done
        fi
        warn "lore-server needs a restart to pick this up:"
        warn "  sudo systemctl daemon-reload && sudo systemctl restart loreserver"
    else
        log "Left lore-server integration in place."
    fi
else
    log "No lore-server integration artifacts found — nothing to revert."
fi

# Note: /opt/arclore-deploy (the exported cert copy) is left in place; it is just
# a copy of the cert and harmless. Remove it by hand if desired.
[[ -d "$DEPLOY_DIR" ]] && KEPT+=("$DEPLOY_DIR/ (exported cert copy — remove manually if unwanted)")

# ──────────────────────────────────────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────────────────────────────────────
hdr "Summary"
if [[ ${#REMOVED[@]} -gt 0 ]]; then
    echo "${C_OK}Removed:${C_RESET}"
    for r in "${REMOVED[@]}"; do echo "  - $r"; done
else
    echo "Removed: (nothing found)"
fi
if [[ ${#KEPT[@]} -gt 0 ]]; then
    echo "${C_WARN}Kept:${C_RESET}"
    for k in "${KEPT[@]}"; do echo "  - $k"; done
fi
ok "Uninstall complete."
