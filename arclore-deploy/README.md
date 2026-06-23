# arclore-deploy

One-command deployment for the self-hosted **ArcLore** control plane.

## What this is

The ArcLore stack is three services. This deployer installs the **two that are
ours**; the third (Epic's `lore-server`) is deployed separately by the operator
and only *pointed at* the auth service.

| Service | Lang | Role | Ports | Installed here? |
|---|---|---|---|---|
| **arc-lore-auth** | Go | JWKS + gRPC auth control plane | HTTP `:8080`, gRPC TLS `:8443` | yes |
| **ArcLoreWeb** | Go | web frontend (login + browse) | HTTP `:41380` | yes |
| **lore-server** | Rust (Epic) | the actual Lore VCS server | gRPC `:41337`, HTTP `:41339` | **no** — operator deploys; this can patch its config |

Everything `arc-lore-auth` owns lives in its own self-contained directory
`/opt/arc-lore-auth/`: the binary, `config.toml`, the SQLite DB
(`arc-lore.db`), the self-signed TLS cert/key for `:8443` (`arc-lore-auth-tls.crt`,
SAN = your `LORE_HOST`), and the RSA signing key + issue secret
(`arc-lore-auth.key` / `.secret`). All auto-generated on first start. The
**first user registered** via ArcLoreWeb becomes admin.

## ArcLoreWeb browsing features

Once deployed, ArcLoreWeb provides these read-mostly browse capabilities:

**Branch switcher** — the repo home page (`/{owner}/{repo}`) includes a branch dropdown.
Append `?branch=<name>` to the URL or select from the dropdown to view the tree, file
content, and commit history at that branch. The switcher is only on the repo-home view;
file and commits pages carry the branch in their URL path (`/src/branch/{branch}/…`).

**Locks page** — each repo has a **Locks** tab (`/{owner}/{repo}/locks/branch/{branch}`)
listing every file locked on that branch: path, lock owner, and time. The view is
read-only (unlock is not yet wired in the UI; use the `lore` CLI to release locks).

## Scripts

| Script | Where | Purpose |
|---|---|---|
| `install.sh` | Linux server (root) | build + install + start both services; export cert; optionally patch lore-server |
| `update.sh` | Linux server (root) | rebuild + swap binaries + restart only; preserves config/DB/cert/units/lore-server |
| `uninstall.sh` | Linux server (root) | stop + remove both services; keep or purge data; optionally revert lore-server edits |
| `install-windows.ps1` | each Windows **editor** host (admin) | install/verify the TLS cert into `LocalMachine\Root` so the UE plugin trusts `:8443` |
| `systemd/arcloreweb.service` | — | reviewable template for the ArcLoreWeb unit `install.sh` generates |

`install.sh` reuses the **existing** `arc-lore-auth.service` unit from
`arc-lore-auth/deploy/` (it is not duplicated here).

## Linux install (one command)

```sh
git clone https://github.com/iniside/ArcLore.git
sudo ./ArcLore/arclore-deploy/install.sh
```

`install.sh` builds from the sibling `arc-lore-auth/` and `ArcLoreWeb/` dirs in
the clone. If you downloaded `install.sh` by itself, it clones ArcLore into a
temp dir and builds from there (override the URL with `--repo`).

It prompts for `LORE_HOST` (IP/hostname editors use — drives `tls_san`,
`audience`, `web_base_url`, and ArcLoreWeb's lore-server addresses), `TOKEN_TTL`,
`ADMIN_SECRET` (random if blank), and `WEB_LISTEN`. Non-interactive:
`sudo ./install.sh -y` (defaults), or pre-seed via env
(`LORE_HOST=… ADMIN_SECRET=… sudo -E ./install.sh -y`).

**Re-runs preserve configs by default** (idempotent upgrade): an existing
`config.toml` is kept, the `SESSION_SECRET` is reused from the existing unit (so
live web sessions survive), and the lore-server `[server.auth]` block is left
alone if already present. Pass **`--overwrite`** to flip all of that: regenerate
`config.toml` from the prompts, rotate `SESSION_SECRET`, and **force-set** the
lore-server auth keys (`jwt_audience` / `jwk.endpoint` / `auth_url`) in place —
useful when `LORE_HOST` or any value changed and you want the new values applied
without hand-editing.

Requires **Go ≥ 1.24** and **git** already installed (it will not install a Go
toolchain — it prints instructions and exits).

After install:

1. Open `http://<LORE_HOST>:41380` → sign-in / first-run setup to create the
   admin user.
2. Trust the cert on each Windows editor host (below).
3. Apply the lore-server config block (below) if not auto-applied.

## Update (in-place binary swap)

To ship new code to an already-installed stack without re-running setup:

```sh
cd ArcLore && git pull
sudo ./arclore-deploy/update.sh
```

`update.sh` rebuilds the two Go binaries (same source resolution as `install.sh`
— sibling dirs, else clone) and swaps them in `/opt` + restarts the services. It
deliberately **touches nothing else**: `config.toml`, the SQLite DB, the RSA
signing key (so the JWKS `kid` is unchanged — existing tokens keep validating,
**no Windows cert re-trust, no lore-server restart**), the TLS cert/key, the
systemd units, and Epic's lore-server are all left as-is. For first install, or
to change config / regenerate certs / re-wire lore-server, use `install.sh`.

- `--auth-only` / `--web-only` — update just one service.
- `--pull` — `git pull --ff-only` the source checkout before building.
- `--repo URL` — git URL for the clone fallback.

After restart, it waits on `arc-lore-auth`'s `/healthz` and ArcLoreWeb's listen
port and reports.

> **Token-claim changes need a re-login.** If an update changes what goes *into*
> a token (e.g. the admin permission set), existing tokens still carry the old
> claims — affected users must log out / back in on the web, or `lore login`
> again on the CLI, to mint a fresh token. The signing key is unchanged, so this
> is a re-login, not a re-trust.

## Uninstall

```sh
sudo ./arclore-deploy/uninstall.sh           # keeps data (DB, keys, cert)
sudo ./arclore-deploy/uninstall.sh --purge   # also wipes data
```

Requires typing `yes`. By **default it keeps** the SQLite DB, RSA signing key,
issue secret, and TLS cert/key, so a reinstall preserves users and does not
invalidate issued tokens. `--purge` (or answering `yes` to the wipe prompt)
deletes them. It also offers (default No) to revert the lore-server edits.

## Windows editor-host cert install

The UE Lore plugin verifies the `:8443` TLS cert against the Windows trust store
(there is no skip-verify). By **default the script fetches the cert straight from
the server's `:8443` TLS handshake** — the cert you need to trust is the one the
server presents — so no SSH, no scp, no file copy, no credentials (scp wouldn't
work anyway: the server's SFTP subsystem is disabled). It always grabs the
**current** cert, so re-running after a cert rotation just works. In an
**elevated** PowerShell:

```powershell
# fetch from the default server (159.69.137.186:8443) and install
.\install-windows.ps1

# fetch from a different host
.\install-windows.ps1 -Server lore.lan

# or install from a local copy instead of fetching
.\install-windows.ps1 -CertPath .\arc-lore-auth-tls.crt

# remove it
.\install-windows.ps1 -Uninstall
```

This is trust-on-first-use over the LAN — the same trust model as the rest of the
self-host setup. The `-Server` host must match the host in lore-server's
`auth_url`.

The cert SAN must equal the host the editor dials in `auth_url`
(`https://<host>:8443`). IP-vs-hostname mismatch → TLS handshake failure.

## lore-server config (manual reference)

Add to Epic's lore-server config (`/opt/loreserver/config/*.toml`), replacing
`HOST` with your `LORE_HOST`:

```toml
[server.auth]
jwt_audience = ["HOST"]          # MUST equal arc-lore-auth's `audience` exactly

[server.auth.jwk]
endpoint = "http://HOST:8080/jwks.json"

[environment.endpoint]
auth_url = "https://HOST:8443"   # host MUST equal arc-lore-auth's tls_san
```

`lore-server` also makes its **own outbound** rebac/lookup calls to the auth
service and verifies TLS via rustls `.with_native_roots()`. A `CA:FALSE`
self-signed leaf is excluded by `update-ca-trust`, so point lore-server at a
bundle that includes the auth cert:

```sh
cat /etc/pki/tls/certs/ca-bundle.crt /opt/arc-lore-auth/arc-lore-auth-tls.crt \
  > /opt/loreserver/auth-ca-bundle.crt
```

systemd drop-in `/etc/systemd/system/loreserver.service.d/ssl-cert-file.conf`:

```ini
[Service]
Environment=SSL_CERT_FILE=/opt/loreserver/auth-ca-bundle.crt
```

```sh
sudo systemctl daemon-reload && sudo systemctl restart loreserver
```

`install.sh` applies all of the above as a single default-Yes step: it skips the
auth block if already present, (re)builds the trust bundle with the current cert,
and restarts `lore-server` (loading the new cert trust + re-fetching JWKS). A
`.bak` is taken before any config edit. `arc-lore-auth` must be running before
`lore-server` starts — it fetches JWKS at boot, not lazily.

## HTTPS / reverse proxy

ArcLoreWeb serves **plain HTTP on `:41380` by design** and is intended to run
behind a TLS-terminating reverse proxy (nginx, Caddy, etc.). There is no
in-process TLS option.

### Environment knobs for proxied deployments

When the proxy terminates TLS, add these `Environment=` lines to
`arcloreweb.service` (under `[Service]`):

```ini
Environment=SESSION_COOKIE_SECURE=true
Environment=CSRF_TRUSTED_ORIGINS=https://<public-host>
Environment=TRUST_FORWARDED_FOR=true
```

**`SESSION_COOKIE_SECURE=true`** — marks the session cookie `Secure` so the
browser only sends it over HTTPS (the browser-to-proxy leg). Without it the
cookie is transmitted fine over HTTPS but is **not** flagged `Secure`, so
some browsers may warn or future policy may drop it. Do **not** set this when
ArcLoreWeb is accessed directly over plain HTTP — the browser will refuse to
send the cookie and every request will land on the login page.

**`CSRF_TRUSTED_ORIGINS=https://<public-host>`** — the `net/http`
`CrossOriginProtection` middleware checks `Origin` against the request `Host`.
When a reverse proxy rewrites `Host` to the internal address, the browser's
`Origin` (the public HTTPS origin) no longer matches, and same-site form POSTs
are blocked with 403. Adding the public origin here tells the middleware to
accept it. Comma-separate multiple origins if needed
(`https://lore.example.com,https://lore-alt.example.com`).

**`TRUST_FORWARDED_FOR=true`** — the web-tier login rate-limiter keys on the
client IP. Without this flag it uses `RemoteAddr`, which is the proxy's IP —
all browsers share one bucket and a single misbehaving client can lock out
everyone. With this flag it reads the leftmost `X-Forwarded-For` entry (the
real browser IP). **Only set this when you are genuinely behind a trusted
proxy** — `X-Forwarded-For` is trivially spoofed by a direct client.

### nginx

```nginx
server {
    listen 443 ssl;
    server_name lore.example.com;

    ssl_certificate     /etc/ssl/certs/lore.example.com.crt;
    ssl_certificate_key /etc/ssl/private/lore.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:41380;

        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Origin            $http_origin;
    }
}
```

### Caddy

```caddy
lore.example.com {
    reverse_proxy 127.0.0.1:41380 {
        header_up Host              {host}
        header_up X-Forwarded-For   {remote_host}
        header_up X-Forwarded-Proto {scheme}
        header_up Origin            {http.request.header.Origin}
    }
}
```

Caddy provisions and renews TLS automatically. The `header_up` directives
ensure `CrossOriginProtection` sees the correct public origin.

## Security notes

- `/login`, `/admin`, and ArcLoreWeb run over **plain HTTP** — use only on a
  trusted LAN or behind a TLS-terminating reverse proxy (see above).
- `/opt/arc-lore-auth/config.toml` (holds `admin_secret`) and `arcloreweb.service`
  (holds `SESSION_SECRET`) are written `0600`, root-only.
- Both services run with `ProtectHome=true`: all of `arc-lore-auth`'s state
  (signing key, issue secret, DB, cert) is pinned under `/opt/arc-lore-auth/`,
  not root's home, so the stricter sandbox profile is safe.

## Logs

```sh
journalctl -u arc-lore-auth -f
journalctl -u arcloreweb -f
```
