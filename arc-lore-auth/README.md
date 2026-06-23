# arc-lore-auth

A small standalone Go service that issues signed JWT tokens for a self-hosted
[Lore](https://github.com/EpicGames/lore) server. It holds an RSA-2048 keypair,
serves a JWKS endpoint the Lore server fetches, and issues per-user tokens over HTTP.

**Production deploy:** see [INSTALL.md](INSTALL.md) for the full install / deploy runbook
(binary build, config, systemd unit, firewall, cert import, user creation, troubleshooting).

This is Step 2 of the ArcLore self-host login plan (gRPC exchange added in Step 3).

## Why this exists

The Lore server validates every request via JWT bearer tokens against a JWKS endpoint.
Interactive (browser) login is Epic-hosted only. The only self-host path is
`lore_auth_login_with_token(token, "lore")` — which validates the token locally and
stores it, with no UCS exchange. This service provides the JWT issuer half of that
contract.

## Self-host auth: full setup

### The two-leg token model

The Lore client uses **two distinct tokens** for a self-hosted server with auth enabled:

1. **Authn token** — a long-lived personal token stored by `login_with_token "lore"`. This
   proves identity to `arc-lore-auth`. It is minted once (via `arc-lore-auth mint` or the
   interactive `/login` flow) and lives in the editor's credential store.

2. **Authz token** — a short-lived per-request token that carries `resources: ["urc-*"]`.
   On every repo op (lock, commit, status) the editor calls this service's gRPC endpoint
   `ExchangeUserTokenForMultiresourceToken`, sending the authn token as a Bearer in the
   `authorization` metadata header. This service verifies the authn token's RS256 signature
   (only holders of a token *we* signed can obtain an authz token — see security note below),
   then mints and returns an authz token. The lore server validates the authz token against
   the JWKS endpoint.

Without the exchange service running, enabling `[server.auth]` on the lore-server causes
every repo op to 401 — the editor cannot get an authz token with resource grants.

### Run order

**Always start `arc-lore-auth` before `lore-server`.** The lore-server fetches the JWKS at
boot only (not lazily per request) and aborts if the JWKS endpoint is unreachable.

Both ports must be reachable from the lore-server host (JWKS over HTTP) and from every
editor host (gRPC exchange over TLS). Apply firewall rules accordingly.

```sh
# 1. Start arc-lore-auth first
./arc-lore-auth -config /path/to/config.toml

# 2. Then start lore-server
lore-server -config /path/to/lore-server-config.toml
```

### lore-server config block

Add to the lore-server's `config.toml`:

```toml
[server.auth]
# jwt_audience MUST be set — the Rust jsonwebtoken crate validates aud by default,
# and rejects any token carrying an aud claim if no expected audience is configured.
# Set it to exactly the value of arc-lore-auth's `audience` field (the lore-server
# host domain/IP, e.g. "159.69.137.186" or "lore-server.internal").
jwt_audience = ["<audience>"]   # MUST equal arc-lore-auth's `audience` config value
# jwt_issuer — leave UNSET unless you also set arc-lore-auth `issuer` to match;
# the server only validates issuer when explicitly configured.
[server.auth.jwk]
endpoint = "http://<authhost>:<jwks-http-port>/jwks.json"
# e.g. endpoint = "http://192.168.1.10:8080/jwks.json"

[environment.endpoint]
auth_url = "https://<authhost-matching-tls_san>:8443"
# e.g. auth_url = "https://192.168.1.10:8443"
```

**`auth_url` constraints:**

- The host portion of `auth_url` MUST equal `tls_san` in `arc-lore-auth`'s config —
  the gRPC client verifies the TLS cert SAN against the host it connects to.
- `auth_url` must be non-empty and stable (a missing or wrong value causes the editor
  to silently store nothing on login).
- `auth_url` must use `https://` (the gRPC exchange transport is always TLS).

> **(N1) Caution:** the `[environment.endpoint]` block here sets only `auth_url`. If after
> adding this block the editor stops resolving `repository_url`, `storage_url`,
> `revision_url`, or `lock_url` from the connect remote, also populate those fields to
> match the remote. Verify on first end-to-end run.

### TLS cert install — the operational catch

The editor's gRPC client verifies the exchange certificate against the **OS trust store**.
There is no skip-verify option; it is baked into `lore.dll`. The QUIC/HTTP skip-verify
setting does NOT apply to the gRPC exchange.

**Install the generated self-signed cert on every editor host's Trusted Root store:**

**Windows (run as Administrator):**

```cmd
certutil -addstore Root arc-lore-auth-tls.crt
```

or: MMC → Certificates (Local Computer) → Trusted Root Certification Authorities →
Import `arc-lore-auth-tls.crt`.

**Linux:**

```sh
sudo cp arc-lore-auth-tls.crt /usr/local/share/ca-certificates/arc-lore-auth.crt
sudo update-ca-certificates
```

**macOS:**

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain arc-lore-auth-tls.crt
```

The cert file is written to the path set in `tls_cert_path` (default:
`./arc-lore-auth-tls.crt` in the working directory). On first run `arc-lore-auth` prints
the exact `certutil` command for the generated cert.

**SAN type must match `auth_url` host:** if `auth_url` uses an IP (`https://192.168.1.10:8443`),
set `tls_san = "192.168.1.10"` — the cert gets an IP-SAN. If `auth_url` uses a hostname
(`https://lore-auth.internal:8443`), set `tls_san = "lore-auth.internal"` — the cert gets
a DNS-SAN. An IP-in-DNS or DNS-in-IP mismatch causes a TLS handshake failure.

### Cert renewal

Self-signed certs are generated with ~825-day validity (the CA/Browser-Forum max for leaf
certs). To renew:

1. Delete `tls_cert_path` and `tls_key_path` from disk.
2. Restart `arc-lore-auth` (a new cert is generated automatically).
3. Re-install the new cert on all editor hosts (repeat the trust-store import above).

### Verification quick-path

```sh
# 1. Mint an authn token for a user
./arc-lore-auth mint --user <name> --audience <lore-server-host>

# 2. Paste the printed JWT into the editor:
#    ArcLore panel → Login → token type "lore" → paste → Login
#    Status should show "Signed in: <name>"

# 3. Perform a repo op (lock any file)
#    The lock owner should display as "<name>", not "<unknown>"
```

If the owner shows `<unknown>`, the gRPC exchange is not reachable or the cert is not
trusted. Check: (a) `arc-lore-auth` is running and gRPC port is open, (b) the cert is
installed on the editor host, (c) `tls_san` matches the `auth_url` host.

---

## Data store — SQLite

As of 2026-06-22 (Phase 1–3 rollout) all identity, resource, and grant state lives in a
SQLite database (`db_path`, default `./arc-lore.db`). The old JSON `users_file`
(`./arc-lore-users.json`) is **legacy import only**: if it exists on first startup it is
imported once (the first user in the file is marked admin), then ignored. Delete it after
the import to avoid confusion.

The database is created and migrated automatically on startup (embedded goose migrations).
Schema:

```sql
-- users: identity + argon2id hash + is_admin flag
users (username PK, display_name, argon2id, is_admin, created, updated)

-- resources: registered repositories (resource_id = "urc-{repo-uuid-hex}")
resources (resource_id PK, name, created)

-- grants: per-user per-resource permissions
grants (username, resource_id, permission)  -- PK on all three
-- permission ∈ read|write|owner|admin|obliterate|migrate

-- config: key/value (registration_open etc.)
config (key PK, value)
```

**Effective-resources rule** (governs both token minting and `LookupUserPermissions`):

- Admin users receive all registered repos as concrete entries
  (`{urc-{repoid}, [read,write,owner,admin]}`) **plus** the wildcard
  `{urc-*, [read,write,migrate,obliterate]}` (covers future repos and wildcard-aware ops).
- Non-admin users receive exactly their `grants` rows grouped by `resource_id`.
- A user with no grants gets an empty resource list — never `urc-*`.
- An unknown `sub` (not in `users`) fails closed: empty resources / auth error.
  Never mints `urc-*` for an unknown subject.

## Self-service

### Registration

Self-registration is **admin-toggled** and **closed by default** after the first admin is
created via `/api/setup`. An admin re-opens it via the Users page in ArcLoreWeb or
directly:

```sh
curl -X POST http://<authhost>:8080/api/admin/registration \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"open": true}'
```

While open, anyone can register without a token:

```sh
curl -X POST http://<authhost>:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"atleast12chars"}'
```

`/api/register` enforces server-side: registration must be open (403 if closed),
username 3–32 characters (400), password ≥ 12 characters (400), unique username (409).
On success it returns a token and the user is **non-admin** with zero repo grants.

### Self password change

Any logged-in user can change their own password (no admin required):

```sh
curl -X POST http://<authhost>:8080/api/me/password \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"current":"oldpassword","new":"newpassword12"}'
```

The current password is **re-verified** on every call (a stolen session cannot silently
take over the account). New password must be ≥ 12 characters and differ from current.
Returns 200 on success; 401 if current is wrong; 400 for policy violations. The current
session token remains valid after a password change.

This endpoint is **rate-limited per user** (burst 5, 1 token refilled every 30 s).
Rapid successive calls from the same account (e.g. a brute-force loop guessing the
current password) are answered with 429 after the burst is exhausted. Other users are
unaffected — the bucket is keyed by the JWT `sub` claim, not the client IP.

---

## First-run: first admin

On a fresh database the first `POST /api/setup` call atomically inserts the user as admin
and closes registration (sets `config.registration_open = false`). The single-connection
pool (`SetMaxOpenConns(1)`) serialises concurrent requests so exactly one wins — the
second gets a 409. After setup, the only way to add more users is via the management API
(`POST /api/users`) with an admin bearer token.

## Management API (`/api/*`)

arc-lore-auth exposes a JSON management API on `web_listen_addr` (default `:8080`).
ArcLoreWeb uses this for native login, first-run setup, and the admin management screens.

**Public endpoints (no authentication):**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/status` | `{has_users, registration_open}` — drives first-run gate |
| `POST` | `/api/setup` | `{username, password, display_name}` — create first admin + auto-login (409 after first run) |
| `POST` | `/api/login` | `{username, password}` → `{token, expires_at, user_id, name, is_admin}` |
| `POST` | `/api/register` | `{username, password}` — open self-registration (403 when closed; 400 if username < 3 or > 32 chars, password < 12; 409 duplicate) |

`setup`, `login`, and `register` are per-IP rate-limited.

**Authenticated (any user) endpoints (require `Authorization: Bearer <token>`):**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/me/password` | `{current, new}` — change own password; re-verifies `current` every call |

**Admin endpoints (require `Authorization: Bearer <admin-token>`):**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/admin/registration` | `{open: bool}` — toggle self-registration open/closed |
| `GET` | `/api/users` | List all users (no hash field) |
| `POST` | `/api/users` | `{username, password, display_name, is_admin}` → create user |
| `DELETE` | `/api/users/{name}` | Delete user (409 if last admin) |
| `POST` | `/api/users/{name}/password` | `{password}` → replace password |
| `POST` | `/api/users/{name}/admin` | `{is_admin}` → toggle admin (409 if last admin demotion) |
| `GET` | `/api/resources` | List registered repos (resource_id, name, created) |
| `GET` | `/api/users/{name}/grants` | Get user's grants as `resource_id → [permissions]` |
| `POST` | `/api/grants` | `{username, resource_id, permission}` → add grant |
| `DELETE` | `/api/grants` | `{username, resource_id, permission}` → revoke grant |

## Interactive login + user accounts

### Accounts

**First admin — via `/api/setup` (recommended):** run `ArcLoreWeb` and open `/setup`, or:

```sh
curl -X POST http://<authhost>:8080/api/setup \
  -H "Content-Type: application/json" \
  -d '{"username":"lukasz","password":"...", "display_name":"Lukasz Baran"}'
```

This only works when the database is empty. Returns an authn token on success.

**Additional users — via the API (admin token required):**

```sh
curl -X POST http://<authhost>:8080/api/users \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"...","display_name":"Alice"}'
```

**Via the CLI (no daemon needed — writes directly to the DB):**

```sh
./arc-lore-auth useradd lukasz
# Prompts: "Password:" then "Confirm password:" — no echo
# Optional: --display-name "Lukasz Baran"
./arc-lore-auth userlist        # list all users
./arc-lore-auth userdel lukasz  # delete a user
./arc-lore-auth setpw lukasz    # change password (prompts)
```

Passwords are hashed with argon2id (PHC format `$argon2id$v=19$m=…`). The database
file is never written in plaintext.

### The three endpoints — who hits what

| Endpoint | Protocol | Bind | Who connects |
|----------|----------|------|-------------|
| **JWKS** — `/jwks.json` | HTTP | `web_listen_addr` (e.g. `0.0.0.0:8080`) | **lore-server** fetches at boot |
| **Management API** — `/api/*` | HTTP/JSON | `web_listen_addr` | **ArcLoreWeb** (login, setup, admin screens) |
| **Web login + admin** — `/login`, `/admin` | HTTP | `web_listen_addr` | **lore CLI** (browser-based interactive login) |
| **gRPC exchange + session** — `StartAuthSession`, `GetAuthSession`, `ExchangeUserTokenForMultiresourceToken` | TLS gRPC | `grpc_listen_addr` (e.g. `0.0.0.0:8443`) | **lore CLI / editor** |

`web_base_url` is NOT a second listener — it is the externally-reachable form of `web_listen_addr`. The daemon always binds `web_listen_addr`; `web_base_url` is only used to build the `login_url` string returned by `StartAuthSession`.

### Interactive login flow (confirmed CLI path)

```sh
lore auth login <your-lore-remote>
```

1. The lore CLI calls `StartAuthSession` (gRPC TLS on `auth_url` / `grpc_listen_addr`).
2. arc-lore-auth creates a pending session, builds `login_url = <web_base_url>/login?session=<code>`, and returns it.
3. The CLI opens `login_url` in the artist's default browser (`--no-browser` prints the URL instead).
4. The artist signs in at the `/login` page (username + password, verified against the SQLite store).
5. On success the server marks the session complete with a minted authn token.
6. The CLI polls `GetAuthSession` (30 × 5 s = 150 s window) until the token is ready, then stores it in the lore credential store keyed by `(auth_url, identity)`.
7. The editor's subsequent repo ops (lock, commit, status) present that stored token — they are now authenticated and the lock owner displays as the signed-in username.

> **Deferred — in-editor interactive-login button:** the "Login" button inside the UE editor that triggers `lore_auth_login_interactive` is not yet wired (it needs a 150 s async poll harness). Trigger interactive login via the `lore` CLI for now; the editor consumes the stored token automatically.

### lore-server config (Phase 2 carry-over, also needed for interactive login)

```toml
[server.auth]
# jwt_audience MUST be set — the Rust jsonwebtoken crate validates aud by default.
# Use exactly the value of arc-lore-auth's `audience` field.
jwt_audience = ["<tls_san / audience>"]   # MUST equal arc-lore-auth's `audience` value
# jwt_issuer — leave UNSET unless you also set arc-lore-auth `issuer` to match.
[server.auth.jwk]
endpoint = "http://<authhost>:8080/jwks.json"   # plain HTTP — web_listen_addr

[environment.endpoint]
auth_url = "https://<tls_san>:8443"             # TLS gRPC — grpc_listen_addr
# auth_url host MUST equal tls_san; the gRPC client enforces the SAN match.
```

`jwt_issuer` may remain unset (issuer is only validated when explicitly configured).
`jwt_audience` MUST be set — see the critical note in the Quick Start below.

### SECURITY — plain HTTP

> **WARNING:** `/login` and `/admin` are served over **plain HTTP**. Passwords and the admin secret travel across the network **in cleartext**. Use this service only on a **trusted private network** (home lab, dedicated studio LAN). Placing a TLS-terminating reverse proxy (nginx, Caddy) in front and pointing `web_base_url` at the HTTPS URL is a supported follow-up but is out of scope for this release. Do **not** expose `web_listen_addr` to the public internet without TLS.

---

## Quick start

### 1. Build

```sh
cd arc-lore-auth   # from the ArcLore/ folder
go build ./...
```

The C++ plugin build has **zero dependency on Go** — UBT never calls `go build`.

**Server is on Linux?** Cross-compile from any host (pure Go, no C toolchain needed):

```sh
make linux            # → arc-lore-auth-linux-amd64 (static, CGO disabled)
# or directly:
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o arc-lore-auth-linux-amd64 .
```

`make all` builds linux-amd64, linux-arm64, windows, and darwin-arm64. Copy the binary to the
Lore-server host and run it there. (Cross-built binaries are git-ignored.)

### 2. Configure

Copy `config.toml` and set at minimum:

```toml
audience = "my-host.lan"   # MUST be your lore-server's hostname — see below
```

### 3. Start arc-lore-auth BEFORE lore-server

**The lore-server fetches JWKS at startup** (startup-only, not lazily per request). If
the auth service is not running when lore-server boots, it will abort. Always start
`arc-lore-auth` first:

```sh
./arc-lore-auth -config /path/to/config.toml
```

On first run it:

- Generates an RSA-2048 key → `~/.arc-lore-auth/arc-lore-auth.key`
- Generates an issue secret → `~/.arc-lore-auth/arc-lore-auth.secret`
- Prints the issue secret to stdout — **save it**.

Then start lore-server.

### 4. Configure lore-server

Add to your lore-server `config.toml`:

```toml
[server.auth]
# jwt_audience MUST be set. The Rust jsonwebtoken crate's validate_aud defaults to
# true: with NO expected audience configured it rejects any token that carries an aud
# claim — which ours always does. Set it to exactly arc-lore-auth's `audience` value.
jwt_audience = ["<audience>"]   # e.g. ["192.168.1.10"] or ["lore-server.internal"]
# jwt_issuer — leave UNSET unless you also set arc-lore-auth `issuer` to match;
# issuer is only validated when explicitly configured on the server.
[server.auth.jwk]
endpoint = "http://127.0.0.1:8080/jwks.json"
```

**Do not set `jwt_issuer`** unless you also configure a matching `issuer` in arc-lore-auth's
config. **`jwt_audience` MUST be set** — the JWKS signature check alone is not sufficient
because the crate's audience validator also fires and rejects tokens with an unmatched `aud`.

### 5. Mint a token and test offline first

Before wiring the editor integration, verify the round-trip manually:

```sh
./arc-lore-auth mint --user lukasz
```

This prints a JWT to stdout (no server, no secret needed). Paste it into ArcLore's
existing **"Login with token"** field and confirm:

- Status shows "Signed in: lukasz"
- A subsequent op (status/commit) actually carries the Bearer (not a silent no-op)

Only trust the Go-fetch flow once the offline paste works end-to-end.

You can also write the token to a file:

```sh
./arc-lore-auth mint --user lukasz --out token.txt
```

The `mint` subcommand is the manual token-minting path; it runs offline and does
not require the daemon.

---

## CRITICAL: the `audience` field

**`audience` must equal your lore-server's host domain**, e.g. `"my-host.lan"`,
`"lore-server.internal"`, or `"192.168.1.10"` (as a bare IP, though a hostname is
preferred).

The in-editor Lore client validates tokens with:

```text
remote_domain.ends_with(any(aud ∪ {iss}))
```

If `audience = "lore"`, this will only pass if your server is hosted at a domain
ending in `"lore"`. **Do not use `"lore"` as the audience.**

There is no sensible default. The service refuses to start without it.

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/jwks.json` | JWKS (public key for token verification) |
| `GET` | `/.well-known/jwks.json` | Same JWKS, alternate well-known path |
| `GET` | `/healthz` | Liveness probe → `200 ok` |
| `GET` | `/api/status` | `{has_users, registration_open}` (public) |
| `POST` | `/api/setup` | Create first admin + auto-login (public; 409 after first run) |
| `POST` | `/api/login` | Credential login → token (public; rate-limited) |
| `POST` | `/api/register` | Open self-registration → token (public; 403 when closed) |
| `POST` | `/api/me/password` | Change own password (any authed user) |
| `POST` | `/api/admin/registration` | Toggle registration open/closed (admin) |
| `GET` | `/api/users` | List users (admin) |
| `POST` | `/api/users` | Create user (admin) |
| `DELETE` | `/api/users/{name}` | Delete user (admin) |
| `POST` | `/api/users/{name}/password` | Set password (admin) |
| `POST` | `/api/users/{name}/admin` | Toggle admin flag (admin) |
| `GET` | `/api/resources` | List registered repos (admin) |
| `GET` | `/api/users/{name}/grants` | Get user grants (admin) |
| `POST` | `/api/grants` | Add grant (admin) |
| `DELETE` | `/api/grants` | Remove grant (admin) |

## Token shape

Every minted token contains:

| Claim | Value |
|-------|-------|
| `sub` | username (becomes the Lore lock owner) |
| `iss` | `config.issuer` |
| `aud` | `[config.audience]` (JSON array) |
| `iat` | now (unix seconds) |
| `exp` | now + `config.token_ttl` (default 7 days) |
| `name` | username |
| `preferred_username` | username |
| `env` | `config.env` (default `"local"`) |
| `idp` | `config.idp` (default `"arc-lore-auth"`) |
| `resources` | Grant-driven: admin → all repos + `urc-*`; non-admin → exactly their grants; unknown sub → `[]` |
| `is_service_account` | `false` |

Signed RS256. JWT header includes `kid` matching the JWKS key's `kid` (SHA-256 of the
DER-encoded public key — stable across restarts as long as the key file is reused).

## Subcommands

```text
arc-lore-auth [flags]                              # run the HTTP + gRPC daemon (default)
arc-lore-auth mint --user <name>                   # print a JWT to stdout (offline, no daemon needed)
arc-lore-auth print-jwks                           # print the JWKS JSON and exit
arc-lore-auth useradd [--display-name <name>] <u>  # add a user to the SQLite DB (prompts for password, no echo)
arc-lore-auth userlist                             # list all users from the SQLite DB
arc-lore-auth userdel <username>                   # delete a user from the SQLite DB
arc-lore-auth setpw <username>                     # replace a user's password (prompts, no echo)
```

## Flags

```text
-config <path>    path to config.toml (default: config.toml)
-listen <addr>    override listen_addr
-audience <str>   override audience
```

## Configuration reference

See `config.toml` for all fields with documentation. Key ones:

| Field | Default | Notes |
|-------|---------|-------|
| `db_path` | `./arc-lore.db` | SQLite database path; goose migrations run automatically on startup |
| `listen_addr` | `127.0.0.1:8080` | legacy HTTP bind (superseded by `web_listen_addr`; kept for backward compat) |
| `web_listen_addr` | `0.0.0.0:8080` | HTTP bind for JWKS + management API + web login (replaces `listen_addr`) |
| `web_base_url` | *(required for interactive login)* | externally-reachable HTTP base used to build `login_url` (e.g. `http://authhost.lan:8080`); `StartAuthSession` fails closed if unset |
| `grpc_listen_addr` | `0.0.0.0:8443` | gRPC bind address (TLS; `UrcAuthApi` exchange + session + `RebacApi` registry) |
| `tls_cert_path` | `./arc-lore-auth-tls.crt` | TLS cert PEM for gRPC listener |
| `tls_key_path` | `./arc-lore-auth-tls.key` | TLS key PEM for gRPC listener |
| `tls_san` | *(required)* | SAN for auto-generated cert; MUST equal `auth_url` host |
| `issuer` | `arc-lore-auth` | JWT `iss` claim |
| `audience` | *(required)* | JWT `aud` claim — must be lore-server hostname |
| `env` | `local` | JWT `env` claim |
| `idp` | `arc-lore-auth` | JWT `idp` claim |
| `key_path` | `~/.arc-lore-auth/arc-lore-auth.key` | PKCS#8 PEM JWT signing key |
| `users_file` | `./arc-lore-users.json` | **Legacy import only.** If present on first startup, users are imported once (first user → admin) then the file is ignored. Delete after import. |
| `admin_secret` | *(empty = admin disabled)* | **Legacy.** Unlocks the HTML `/admin` form (superseded by the JSON `/api/*` management API). |
| `session_ttl` | `600` (seconds) | interactive-login session lifetime; keep above 150 s (client poll window) |
| `token_ttl` | `168h` (7 days) | token lifetime |
| `allowed_users` | *(empty = any)* | allowlist of usernames |

## Minting authn tokens

There is no HTTP mint endpoint. Authn tokens are issued either by the interactive
`/login` flow (the editor's Local login button) or manually via the offline `mint`
subcommand:

```sh
./arc-lore-auth mint --user lukasz
```

The gRPC exchange (`ExchangeUserTokenForMultiresourceToken`) carries only
`authorization: Bearer <authn-token>`; its security gate is RS256 Bearer signature
verification — there is no shared-secret header on any endpoint.

## Key stability and rotation

The `kid` (key ID) is a stable SHA-256 hash of the DER-encoded public key. As long as
the key file (`key_path`) is unchanged, `kid` is identical across restarts — so you do
not need to restart lore-server after restarting arc-lore-auth (as long as the lore
server has already fetched the JWKS).

To rotate the key: delete the old key file, restart arc-lore-auth (new key generated),
then restart lore-server (re-fetches JWKS with new kid). Old tokens are immediately
invalid.

## Clock skew

Token `exp` is based on this host's clock. If the lore-server's clock diverges
significantly, tokens may appear expired or not-yet-valid. Sync NTP on both hosts.
The default 7-day TTL gives ample margin for typical drift. Re-mint tokens as needed
(`arc-lore-auth mint` or click Local login in the editor).

## gRPC surface

arc-lore-auth serves two gRPC services on `grpc_listen_addr` (TLS, default `:8443`):

**`UrcAuthApi`** (package `epic_urc`):

- `HealthCheck` — liveness
- `StartAuthSession` / `GetAuthSession` — interactive browser-based login session
- `ExchangeUserTokenForMultiresourceToken` — exchange authn token → grant-scoped authz token
- `LookupUserPermissions` — return caller's effective resource permissions (concrete resource IDs; no `urc-*`); used by lore-server on `RepositoryList`
- `GetUserInfo` / `GetUserId` — user directory lookup from the SQLite store (so the editor shows real display names for lock owners)
- `CheckUserPermission` — per-resource allowed/denied check

**`RebacApi`** (package `ucs.auth`):

- `CreateResource` — called by lore-server on `RepositoryCreate`; registers `urc-{repoid}` + grants creator owner/read/write; idempotent (`ALREADY_EXISTS` → OK)
- `DeleteResource` — called by lore-server on `RepositoryDelete`; removes resource + cascades grants; idempotent (absent → OK; lore maps `NOT_FOUND` → `INTERNAL`)

Both services require the caller to carry a valid RS256 Bearer token (signed by this service). The token is verified against the local public key before any operation — unsigned callers are rejected.

## Trust model

This service is a minimal local issuer — not a production IdP. Anyone with shell access
to the host can mint tokens for arbitrary usernames via the offline `mint` subcommand.
For production deployments, replace with a real IdP (Keycloak, Auth0, etc.) that speaks
the same JWKS contract; no changes to lore-server are needed.

The gRPC exchange endpoint (`ExchangeUserTokenForMultiresourceToken`) requires the caller
to present a valid authn Bearer token in the `authorization` metadata header. The incoming
token is cryptographically verified against **this service's own RSA public key** before
an authz token is minted — only holders of a token we previously signed can obtain an
authz token. A caller who guesses or forges a token sub-claim without a valid signature
is rejected at the RS256 verification step. There is no shared-secret header on any
endpoint — RS256 signature verification is the sole gate on the gRPC exchange path.
