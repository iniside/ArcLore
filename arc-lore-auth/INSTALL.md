# arc-lore-auth — Install & Deploy Runbook

See also: [README.md](README.md) for the token model, endpoint table, config reference, and trust model.

---

## 1. Overview / topology

`arc-lore-auth` is a small Go daemon that acts as the JWT issuer for a self-hosted
[Lore](https://github.com/EpicGames/lore) server.  It exposes **three logical endpoints**,
all from one process:

| Endpoint | Protocol | Port | Who connects |
|---|---|---|---|
| JWKS — `/jwks.json` and `/.well-known/jwks.json` | HTTP | **8080** (`web_listen_addr`) | **lore-server** — fetches at boot only |
| Web login + admin — `/login`, `/admin` | HTTP | **8080** (`web_listen_addr`) | **Artist's browser** — interactive login |
| gRPC exchange + session — `StartAuthSession`, `GetAuthSession`, `ExchangeUserTokenForMultiresourceToken` | TLS gRPC | **8443** (`grpc_listen_addr`) | **lore CLI / editor plugin** |

**Two-leg token model.** When a user logs in, the lore CLI calls `StartAuthSession` over
gRPC (TLS, port 8443); arc-lore-auth builds a `login_url` from `web_base_url` and returns
it.  The CLI opens that URL in the artist's browser; the artist signs in at `/login`
(username + password from `users_file`).  arc-lore-auth marks the session complete and
mints an **authn token** (long-lived, 7-day default).  The CLI polls `GetAuthSession`,
retrieves the token, and stores it in the lore credential store.  On every subsequent repo
op (lock, commit, status) the editor presents that stored authn token to
`ExchangeUserTokenForMultiresourceToken` (gRPC), which cryptographically verifies the
RS256 signature and returns a short-lived **authz token** carrying `resources: ["urc-*"]`.
The lore-server validates the authz token against the JWKS endpoint.

**Topology placeholders used throughout this document:**

- **`AUTHHOST`** — the IP or hostname at which editor clients and the lore-server can reach
  this machine (e.g. `192.168.1.10` or `lore-auth.internal`).
- **`LOREHOST`** — the hostname the Unreal editor uses in its lore remote URL
  (e.g. `lore-server.internal`).  On a single-box setup `AUTHHOST` and `LOREHOST` are
  the same address.

---

## 2. Prerequisites

- **Linux x86-64** (or compile for another target; the binary is pure Go, no libc required).
- **Open TCP 8080 and 8443** in all applicable firewalls.

```sh
# firewalld (RHEL / Fedora / Rocky)
sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=8443/tcp
sudo firewall-cmd --reload

# ufw (Ubuntu / Debian)
sudo ufw allow 8080/tcp
sudo ufw allow 8443/tcp
```

Also open those ports in any cloud-provider console (Hetzner, AWS, GCP security group, etc.).

> **SECURITY:** `/login` and `/admin` are served over **plain HTTP**.  Passwords and the
> admin secret travel in cleartext.  Use this service only on a trusted private network or
> behind a TLS-terminating reverse proxy (nginx, Caddy).  Do **not** expose `web_listen_addr`
> to the public internet without TLS.

---

## 3. Build / obtain the binary

Cross-compile from any machine with Go installed (no C toolchain needed):

```sh
cd arc-lore-auth   # from the ArcLore/ folder

# Option A — make target
make linux
# produces: arc-lore-auth-linux-amd64

# Option B — direct
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arc-lore-auth-linux-amd64 .
```

Copy the binary to the server and make it executable:

```sh
sudo mkdir -p /opt/arc-lore-auth
sudo cp arc-lore-auth-linux-amd64 /opt/arc-lore-auth/
sudo chmod +x /opt/arc-lore-auth/arc-lore-auth-linux-amd64
```

---

## 4. Configure

Copy `config.toml` from the repo and edit it:

```sh
sudo cp config.toml /opt/arc-lore-auth/config.toml
sudo $EDITOR /opt/arc-lore-auth/config.toml
```

**Required fields** — no defaults, the daemon refuses to start without them:

| Field | What to set | Example |
|---|---|---|
| `tls_san` | **AUTHHOST** — must exactly equal the host portion of `auth_url` in lore-server config.  IP → IP-SAN; hostname → DNS-SAN; type must match. | `"192.168.1.10"` |
| `audience` | **LOREHOST** — must be (or be a suffix of) the lore-server's hostname so the in-editor client gate passes.  **NOT** the literal string `"lore"`. | `"lore-server.internal"` |
| `web_base_url` | Externally-reachable HTTP base URL the artist's **browser** can reach.  Used to build the browser `login_url` in `StartAuthSession`.  NOT a second listener. | `"http://AUTHHOST:8080"` |
| `admin_secret` | Long random string to unlock `/admin`.  Empty → `/admin` returns 503. | `$(openssl rand -hex 32)` |

The systemd unit runs with `WorkingDirectory=/opt/arc-lore-auth`, so relative paths in
`config.toml` resolve to `/opt/arc-lore-auth` automatically. TLS cert/key and `users_file`
resolve correctly without pinning. Pin `key_path` explicitly to keep the signing key under
`/opt/arc-lore-auth` (required for `ProtectHome=true` in the reference unit — see the
minimal config snippet below).

**Listener addresses** (keep these as-is for a production install):

```toml
web_listen_addr  = "0.0.0.0:8080"   # HTTP: JWKS + web login/admin
grpc_listen_addr = "0.0.0.0:8443"   # TLS gRPC: exchange + session
```

**Minimal working config snippet** (replace AUTHHOST / LOREHOST):

```toml
tls_san       = "AUTHHOST"
audience      = "LOREHOST"
web_base_url  = "http://AUTHHOST:8080"
admin_secret  = "<output of: openssl rand -hex 32>"

# TLS cert/key and users_file default to ./  (resolved from WorkingDirectory=/opt/arc-lore-auth)
# Pin key_path so the signing key stays under /opt/arc-lore-auth (required by ProtectHome=true).
key_path      = "/opt/arc-lore-auth/arc-lore-auth.key"

web_listen_addr  = "0.0.0.0:8080"
grpc_listen_addr = "0.0.0.0:8443"
```

Other fields (`issuer`, `env`, `idp`, `token_ttl`, `session_ttl`) have
sensible defaults; see `config.toml` for documentation on each.

---

## 5. Install and start the service

```sh
# Stop any nohup instance still holding :8080 / :8443
sudo pkill -f arc-lore-auth-linux-amd64

# Drop any old or broken unit (e.g. a previous lore-user variant)
sudo systemctl disable --now arc-lore-auth 2>/dev/null; true

# Install the unit (copy or heredoc — either works)
sudo cp deploy/arc-lore-auth.service /etc/systemd/system/
# — or:
# cat deploy/arc-lore-auth.service | sudo tee /etc/systemd/system/arc-lore-auth.service

sudo systemctl daemon-reload
sudo systemctl enable --now arc-lore-auth

# Verify startup
sudo systemctl status arc-lore-auth
sudo journalctl -u arc-lore-auth -n 40
ss -ltnp | grep -E ':8080|:8443'
```

**What happens on first start:**

1. The RSA-2048 JWT signing key is generated and written to `key_path`
   (pinned to `/opt/arc-lore-auth/arc-lore-auth.key` in the minimal config above).
2. The TLS cert is generated (self-signed, `~825-day validity`) and written to
   `tls_cert_path` (default `/opt/arc-lore-auth/arc-lore-auth-tls.crt`).  The exact `certutil` install
   command is printed to the journal too.
3. Both listeners start (`web_listen_addr` HTTP, `grpc_listen_addr` TLS gRPC).

The journal startup banner shows the **kid**, **aud**, and **tls_san** — use these to
confirm the signing key was preserved (kid unchanged from before), the audience matches
the lore-server config, and the TLS SAN is correct.

Note the **cert path** from the journal output — you will need it in step 8.

---

## 5a. Hardening (optional)

The primary deployment above runs as **root** with `WorkingDirectory=/opt/arc-lore-auth`
and `ProtectHome=true`. If you want stronger process isolation with a dedicated service
account, here is the dedicated-`lore`-user variant:

1. **Create the service account** and set ownership of the existing directory:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin lore
   sudo chown -R lore:lore /opt/arc-lore-auth
   ```

2. **Ensure all paths in `/opt/arc-lore-auth/config.toml` are pinned** so they resolve
   under `/opt/arc-lore-auth` — the `lore` user's home (`/nonexistent`) would otherwise
   give `key_path` a different home, regenerating the signing key and invalidating all
   existing tokens:

   ```toml
   tls_cert_path = "/opt/arc-lore-auth/arc-lore-auth-tls.crt"
   tls_key_path  = "/opt/arc-lore-auth/arc-lore-auth-tls.key"
   key_path      = "/opt/arc-lore-auth/arc-lore-auth.key"
   users_file    = "/opt/arc-lore-auth/arc-lore-users.json"
   ```

3. **Edit the installed unit** (`/etc/systemd/system/arc-lore-auth.service`) to add
   `User=lore` / `Group=lore` (paths and `ProtectHome=true` are already set):

   ```ini
   [Service]
   User=lore
   Group=lore
   WorkingDirectory=/opt/arc-lore-auth
   ExecStart=/opt/arc-lore-auth/arc-lore-auth-linux-amd64 -config /opt/arc-lore-auth/config.toml
   ProtectHome=true
   ```

4. `sudo systemctl daemon-reload && sudo systemctl restart arc-lore-auth`

   Verify the **kid** in the journal matches the old value — if it changed, the signing
   key was regenerated (check that all paths in step 2 were pinned correctly).

---

## 6. Point lore-server at arc-lore-auth

Add to the lore-server's `config.toml`:

```toml
[server.auth]
# jwt_audience MUST be set. The Rust jsonwebtoken crate's validate_aud defaults to
# true: without an expected audience configured it rejects any token that carries an
# aud claim — which arc-lore-auth tokens always do. The result is every repo op
# (lore status, lock, commit) failing with gRPC status 7 / InvalidAudience and
# remote_authorized: 0, even though `lore auth login` succeeds.
# Set jwt_audience to exactly arc-lore-auth's `audience` config value (LOREHOST).
jwt_audience = ["LOREHOST"]   # MUST equal arc-lore-auth's `audience` field exactly
# jwt_issuer — leave UNSET unless you also set arc-lore-auth `issuer` to match;
# the server only validates issuer when explicitly configured.
[server.auth.jwk]
endpoint = "http://AUTHHOST:8080/jwks.json"

[environment.endpoint]
auth_url = "https://AUTHHOST:8443"
```

> **WARN — exact URL format:** `auth_url` must be `https://AUTHHOST:8443` — no double
> colon, no trailing slash.  A malformed URL (e.g. `https://host::8443` or bare
> `host:8443`) causes lore-server to crash-loop at boot when it tries to parse the
> endpoint.  Double-check the value after editing.

> **NOTE (N1):** the `[environment.endpoint]` block sets only `auth_url` here.  If after
> adding this block the editor stops resolving `repository_url`, `storage_url`,
> `revision_url`, or `lock_url` from the remote, also populate those fields to match your
> lore-server's existing endpoint values.  Verify on the first end-to-end run.

The **host portion of `auth_url` must equal `tls_san`** in arc-lore-auth's config — the
gRPC client verifies the TLS certificate SAN against the host it dials.  There is no
skip-verify option.

**arc-lore-auth must be running before lore-server starts** (the lore-server fetches
JWKS at boot, not lazily; it aborts if the endpoint is unreachable).

Restart lore-server:

```sh
sudo systemctl restart loreserver
```

---

## 7. Create users

**Via CLI** (daemon need not be running):

```sh
/opt/arc-lore-auth/arc-lore-auth-linux-amd64 \
  -config /opt/arc-lore-auth/config.toml \
  useradd lukasz
# Prompts: "Password:" then "Confirm password:" — no echo
# Optional display name: useradd --display-name "Lukasz Baran" lukasz
```

Passwords are hashed with argon2id (PHC format `$argon2id$v=19$m=…`) and written to
`users_file`.  The file is never written in plaintext.

**Via the web `/admin` page:**

1. Start the daemon (step 5).
2. Visit `http://AUTHHOST:8080/admin` in a browser.
3. Enter `admin_secret` in the unlock form (issues a 30-min signed cookie).
4. Use the "Create user" form.  Same page lets you change passwords and delete users.

---

## 8. Per-editor-host: import the TLS cert (Windows)

The lore editor plugin verifies the gRPC TLS certificate against the OS trust store.
There is no skip-verify option; `lore.dll` enforces it.  The QUIC/HTTP skip-verify
setting does **not** apply here.

Copy `/opt/arc-lore-auth/arc-lore-auth-tls.crt` to each Windows editor host, then in
an **elevated** PowerShell:

```powershell
Import-Certificate -FilePath .\arc-lore-auth-tls.crt `
                   -CertStoreLocation Cert:\LocalMachine\Root
```

Alternative (Command Prompt, elevated):

```cmd
certutil -addstore Root arc-lore-auth-tls.crt
```

Or: MMC → Certificates (Local Computer) → Trusted Root Certification Authorities →
Import `arc-lore-auth-tls.crt`.

The cert's SAN must equal `AUTHHOST` exactly (the value you set in `tls_san`).  If
`tls_san` is an IP address the cert has an IP-SAN; if it is a hostname it has a DNS-SAN.
An IP-in-DNS or DNS-in-IP mismatch causes a TLS handshake failure.

---

## 9. Interactive login from the editor host

After the cert is imported, log in from the command line (the in-editor login button
requires a 150-second async poll harness not yet wired in the UE plugin — use the CLI):

```sh
# The remote must use the lore:// scheme — not bare host:port or http://
lore auth login "lore://LOREHOST:41337"
```

1. The CLI calls `StartAuthSession` over gRPC to `AUTHHOST:8443`.
2. arc-lore-auth builds `login_url = http://AUTHHOST:8080/login?session=<code>` and
   returns it to the CLI.
3. The CLI opens `login_url` in the default browser.
4. Sign in with the username and password created in step 7.
5. The CLI polls `GetAuthSession` for up to 150 s, retrieves the minted authn token, and
   stores it in the lore credential store keyed by `(auth_url, identity)`.
6. The editor's subsequent repo ops use that stored token automatically.

Use `lore --debug auth login "lore://LOREHOST:41337"` to see the full gRPC exchange if
anything goes wrong (the `--debug` global flag surfaces errors the default log level
swallows).

---

## 10. Verify

Perform a repo op in the editor (lock any file).  The lock owner should show as the
signed-in **username**, not `<unknown>`.

Quick CLI verification:

```sh
# 1. Mint an authn token offline (no daemon needed)
/opt/arc-lore-auth/arc-lore-auth-linux-amd64 \
  -config /opt/arc-lore-auth/config.toml \
  mint --user lukasz

# 2. Paste the printed JWT into: ArcLore panel → Login → token type "lore" → Login
#    Status should show "Signed in: lukasz"

# 3. Lock a file in the editor → owner shows "lukasz"
```

---

## 11. Cert rotation / maintenance

The TLS cert regenerates **only** when both `tls_cert_path` and `tls_key_path` are absent
at startup.  To rotate (required after changing `tls_san`, or when the cert approaches
expiry at ~825 days):

```sh
sudo systemctl stop arc-lore-auth
sudo rm /opt/arc-lore-auth/arc-lore-auth-tls.crt \
        /opt/arc-lore-auth/arc-lore-auth-tls.key
sudo systemctl start arc-lore-auth
# Check journal for new certutil command, then re-import on all editor hosts
sudo journalctl -u arc-lore-auth -n 20
```

Re-distribute the new cert to all editor hosts (repeat step 8).

**RSA key rotation** (invalidates all existing tokens — all users must re-login):

```sh
sudo systemctl stop arc-lore-auth
sudo rm /opt/arc-lore-auth/arc-lore-auth.key
sudo systemctl start arc-lore-auth
sudo systemctl restart loreserver   # lore-server must re-fetch JWKS with new kid
```

**Token TTL** is controlled by `token_ttl` in `config.toml` (default `168h` = 7 days).
Users see re-login prompts when their token expires.  Clock skew between this host and
the lore-server can cause premature expiry — sync NTP on both.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `lore auth login` hangs at "Authenticating using `https://…:8443`" | gRPC cert not trusted on the client host | Import the cert (step 8); verify with `openssl s_client -connect AUTHHOST:8443` |
| `lore auth login` does nothing / returns immediately without prompting a browser | Remote scheme wrong — must be `lore://host:port`, not bare `host:port` or `http://` | Use `lore auth login "lore://LOREHOST:41337"` (scheme required) |
| TLS handshake failure | cert SAN type mismatch — `tls_san` is an IP but `auth_url` uses a hostname (or vice versa); or cert has `CA:TRUE` (older builds, see below) | Match SAN type; verify `openssl x509 -in arc-lore-auth-tls.crt -noout -text \| grep -A1 "Basic Constraints"` → must show `CA:FALSE` |
| Older builds generated a CA cert | cert was `CA:TRUE`; lore's gRPC client rejects CA certs as leaf | Stop service, delete cert+key, restart to regenerate a correct end-entity cert, re-import |
| lore-server crash-loops at boot | Malformed `auth_url` or `jwk.endpoint` (double colon, missing scheme) | Fix URLs in lore-server config; confirm arc-lore-auth is up before lore-server |
| lore-server aborts with "JWKS unreachable" at boot | arc-lore-auth not started yet, or port 8080 blocked | Start arc-lore-auth first; check `sudo systemctl status arc-lore-auth`; verify firewall |
| Login succeeds but lock owner shows `<unknown>` | `audience` ≠ LOREHOST, or `auth_url` empty / wrong in lore-server env config | Check `audience` in arc-lore-auth `config.toml`; check `[environment.endpoint] auth_url` in lore-server config |
| `/admin` returns 503 | `admin_secret` not set (or empty) in `config.toml` | Set `admin_secret` to a non-empty string and restart |
| Token expired / "not yet valid" errors | Clock skew between auth host and lore-server | Sync NTP; increase `token_ttl` if drift is expected |
| Every repo op fails with gRPC status 7 / `Not allowed (ValidationFailed(Error(InvalidAudience)))`, `remote_authorized: 0` — but `lore auth login` succeeds | `jwt_audience` not set in lore-server `[server.auth]`. The Rust `jsonwebtoken` crate's `validate_aud` defaults to **true**; with no expected audience it rejects every token that carries an `aud` claim. | Add `jwt_audience = ["LOREHOST"]` to lore-server `[server.auth]` (must equal arc-lore-auth's `audience` value exactly), then restart lore-server. |

**`lore --debug`** (global flag) is your first diagnostic tool — it surfaces gRPC error
details and HTTP responses that the default log level hides.

```sh
lore --debug auth login "lore://LOREHOST:41337"
```
