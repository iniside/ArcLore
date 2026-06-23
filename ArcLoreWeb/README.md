# ArcLoreWeb

ArcLoreWeb is a read-mostly browser UI for the Lore VCS — a Gitea/Forgejo-style interface that
lets you browse repositories, file trees, commit history, diffs, and file locks without the
desktop client. It is a native Go gRPC client of the Lore server (no FFI, no `lore.dll`) and is
designed to run on a separate machine from the Lore server and IdP: only network routes to the
Lore gRPC port (41337) and HTTP blob port (41339) are required.

## Prerequisites

- **Go 1.25** or later — <https://go.dev/dl/>
- **buf** — `go install github.com/bufbuild/buf/cmd/buf@latest`
- **templ** — `go install github.com/a-h/templ/cmd/templ@latest`
- Both tools must be on `PATH` (add `%GOPATH%\bin` on Windows, `$GOPATH/bin` on Unix).

Generated files (`gen/` and `web/templates/*_templ.go`) are committed to the repository.
A plain `go build ./cmd/arcloreweb` works from a fresh clone without `buf` or `templ`.
Regenerate only when `.proto` files or `.templ` templates change.

## Build

Use `build.ps1` (PowerShell) or run the three steps manually:

```powershell
.\build.ps1
```

Or step-by-step:

```powershell
buf generate
templ generate
go build ./cmd/arcloreweb
```

The binary is written to the current directory as `arcloreweb.exe` on Windows.

## Configuration

All settings are read from environment variables.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `LISTEN_ADDR` | no | `:41380` | TCP address the web server listens on |
| `LORE_GRPC_ADDR` | **yes** | — | Lore gRPC endpoint. Bare `host:port` = plaintext. Prefix `grpcs://` for TLS |
| `LORE_HTTP_ADDR` | **yes** | — | Lore HTTP blob base URL (e.g. `http://host:41339`) |
| `LORE_TLS` | no | `false` | Explicit TLS override when `LORE_GRPC_ADDR` is a bare host:port |
| `LORE_TIMEOUT` | no | `30s` | Per-Lore-call deadline (Go duration string) |
| `LORE_AUTH_DISABLED` | no | `false` | Skip login; send no Bearer header. Only for a Lore server running without `[server.auth]` |
| `LORE_AUTH_URL` | no | — | Override the auth-service URL (otherwise discovered via `EnvironmentService.EnvironmentGet`) |
| `SESSION_SECRET` | **yes** | — | Key for session cookie integrity (min 32 random bytes recommended) |
| `MGMT_API_ADDR` | **yes** (auth mode) | — | Base URL of arc-lore-auth's HTTP/JSON management API (e.g. `http://authhost:8080`). Required when `LORE_AUTH_DISABLED=false`. Backs native login, first-run setup, and the admin screens. |
| `DEV_USER_SUB` | no | `dev-user` | Synthetic user subject written by the auth-disabled bypass |

## Local run

The fastest way to get started is the `run-local.ps1` helper, which auto-discovers the Lore
server from `.lore/config.toml` and sets `MGMT_API_ADDR` from the same host (port `8080`):

```powershell
.\run-local.ps1
# auth mode; open the URL, sign in with username/password (native form)
.\run-local.ps1 -AuthDisabled
# for a Lore server running without [server.auth]
.\run-local.ps1 -MgmtAddr http://other-host:8080
# override mgmt API address
```

Or run the binary directly. **Auth mode** (default) against an authed Lore server:

**PowerShell:**

```powershell
$env:LORE_GRPC_ADDR   = "159.69.137.186:41337"
$env:LORE_HTTP_ADDR   = "http://159.69.137.186:41339"
$env:SESSION_SECRET   = "change-me-32-bytes-minimum-secret"
.\arcloreweb.exe
```

**Bash:**

```bash
LORE_GRPC_ADDR=159.69.137.186:41337 \
LORE_HTTP_ADDR=http://159.69.137.186:41339 \
SESSION_SECRET=change-me-32-bytes-minimum-secret \
./arcloreweb
```

Then open <http://localhost:41380>. On first run you will be redirected to `/setup` to create the
first admin account. After that, open `/auth/login`, enter your username and password (native
form — no browser redirect).

## Auth modes and deployment

### Mode 1 — Auth (native in-app login)

The default. Set `LORE_AUTH_DISABLED=false` (or leave it unset) against an authed Lore server,
and set `MGMT_API_ADDR` to arc-lore-auth's HTTP address.

**Native login** — `/auth/login` renders a username/password form that posts directly to
`arc-lore-auth`'s `/api/login`. No UCS browser redirect. The UCS `StartAuthSession`/`GetAuthSession`
flow in arc-lore-auth is still available for the UE editor and `lore` CLI but is no longer used
by ArcLoreWeb.

**First-run gate** — on every request ArcLoreWeb checks `/api/status`. If `has_users = false`
the user is redirected to `/setup`, which renders a create-first-admin form. The form posts to
`/api/setup`; on success the new admin is auto-logged in. Once users exist, `/setup` redirects
to the login page.

On **Login**, ArcLoreWeb stores the minted token (user_sub, user_name, identity_token,
is_admin) in the session. Repo-less calls (repository list, repo-by-name lookup) use that
identity token directly.

For each **repo-scoped** page (file tree, file/raw blob, commit history, diffs, locks),
ArcLoreWeb automatically exchanges the identity token for a per-repo **authorization** token via
`UrcAuthApi.ExchangeUserTokenForMultiresourceToken` (`resource_id = ["urc-" + repo_id_hex]`),
caching it per repo until its expiry. This is what satisfies the Lore server's `JWTInterceptor`,
which requires `resources: urc-{repo_id}` claims that a plain identity token does not carry — so
the old OIDC-pass-through limitation no longer applies. If the exchange fails (the user is not
authorized for that repo, or the auth service is unreachable), the repo page renders a clear
403-style "not authorized" message rather than a server error.

### Admin screens (`/admin/*`)

When logged in as an admin, the navigation shows **Admin** links to:

- **Users** (`/admin/users`) — list, create, delete, set-password, toggle-admin. Operations
  call the arc-lore-auth `/api/users` endpoints with the session token.
- **Repos** (`/admin/repos`) — list registered repos via `arc-lore-auth /api/resources` plus
  lore `RepositoryList`; includes a **New repository** form that calls lore `RepositoryCreate`,
  which in turn calls arc-lore-auth `RebacApi.CreateResource` to register the resource and
  grant the creator `owner/read/write`.
- **Grants** (`/admin/grants`) — per-user, per-repo permission assignment via
  `/api/grants` add/remove.

Non-admin users cannot reach `/admin/*` routes (403).

### Mode 2 — Auth-disabled

Set `LORE_AUTH_DISABLED=true`. The Lore server must be running without `[server.auth]` in its
config. Login is bypassed, the identity token is empty, no token exchange runs, and ArcLoreWeb
sends no `Authorization` header on any call. Useful for local servers with auth turned off.

### Separate-machine deployment

The ArcLoreWeb process needs network access to:

- Lore gRPC port (default **41337**) for all browse RPCs.
- Lore HTTP blob port (default **41339**) for file content and raw downloads.
- The auth-service host (discovered via `EnvironmentService.EnvironmentGet`, or set via
  `LORE_AUTH_URL`) for login and per-repo token exchange (auth mode only).

No direct access to the Lore working directory is needed — it is a pure network client.

## Live reload (development)

Install [air](https://github.com/air-verse/air): `go install github.com/air-verse/air@latest`

```powershell
air
```

Air watches `.go` and `.templ` files, re-runs `templ generate`, rebuilds, and restarts the binary.
Config is in `.air.toml`.

## Smoke test (optional, opt-in)

A thin liveness probe lives in `internal/lore/smoke_test.go` (build tag `smoke`).
It dials the server and calls `ListRepositories`; if `LORE_GRPC_ADDR` is unset it skips.

```bash
LORE_GRPC_ADDR=localhost:41337 \
LORE_HTTP_ADDR=http://localhost:41339 \
SESSION_SECRET=test \
go test -tags smoke ./internal/lore/...
```

## Deferred (not in v1)

- Latest-commit-per-file-row in the file table
- Blame view (no server RPC for it)
- Tags (Lore has none — branches only)
- Branch/tag list pages (dropdown covers branch switching)
- Notifications and live updates
- Write operations (commit, lock, unlock)
- Owner namespacing (Lore repos are globally unique by name; owner segment is cosmetic)
