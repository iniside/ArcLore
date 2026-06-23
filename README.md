# ArcLore

Self-hosting stack for **Lore** — the Unreal version-control system this project uses
for binary assets. Lore-server itself (Epic's component) is deployed separately; the
three projects here are the **control plane and web surface** you run alongside it,
plus the scripts that install them.

They form one unit and are mirrored together to the public
[`ArcLore`](https://github.com/iniside/ArcLore) repo (see
[`../git-mirror/mirror-arclore.ps1`](../git-mirror/mirror-arclore.ps1)), each landing as
a top-level subdirectory at the remote root.

## Components

| Directory                          | Language | What it is |
|------------------------------------|----------|------------|
| [`arc-lore-auth`](arc-lore-auth)   | Go       | JWT **auth service** — issues signed authz tokens, serves a JWKS endpoint, exposes a gRPC exchange + JSON management API (users / resources / grants) backed by SQLite. |
| [`ArcLoreWeb`](ArcLoreWeb)         | Go       | Read-mostly **web UI** for Lore (Gitea/Forgejo-style repo, file, commit, diff, and lock browsing) plus admin screens. Native gRPC client to lore-server. |
| [`arclore-deploy`](arclore-deploy) | sh / ps1 | **Deployment scripts** — build, install, update, and uninstall the two services above as systemd units (Linux), plus a Windows cert-trust installer for editor hosts. |

## How they fit together

```text
        editor / browser
              │  identity token
              ▼
        arc-lore-auth ──── JWKS ────►  lore-server  (deployed separately)
         (authz tokens)                     ▲
              ▲                              │ gRPC :41337 / blob :41339
              │  /api mgmt (users, grants)   │
              └──────── ArcLoreWeb ──────────┘
                         (web UI :41380)

        arclore-deploy installs & wires arc-lore-auth + ArcLoreWeb
        (does NOT install lore-server itself)
```

- **arc-lore-auth** is the identity/authorization authority: editors exchange an
  authentication token for a short-lived authorization token carrying resource grants;
  lore-server validates those tokens against this service's JWKS.
- **ArcLoreWeb** connects to lore-server's gRPC (`:41337`) and blob HTTP (`:41339`)
  ports for browsing, and calls arc-lore-auth's `/api/*` management endpoints for login
  and admin (users, repos, grants).
- **arclore-deploy** builds both Go services from their sibling directories
  (`../arc-lore-auth`, `../ArcLoreWeb`) and installs them with config, TLS, and systemd
  units.

## Quick reference

All commands below assume you are **inside this `ArcLore/` folder**.

### arc-lore-auth (Go)

```sh
cd arc-lore-auth
go build ./...                 # native
make linux                     # cross-compile -> arc-lore-auth-linux-amd64
./arc-lore-auth -config config.toml
```

### ArcLoreWeb (Go)

```powershell
cd ArcLoreWeb
.\build.ps1                    # buf generate + templ generate + go build
.\run-local.ps1                # run locally (auth mode); -AuthDisabled for dev
# then open http://localhost:41380
```

### arclore-deploy (Linux, root)

```sh
sudo ./arclore-deploy/install.sh        # build + install both services + systemd units
sudo ./arclore-deploy/update.sh         # rebuild binaries + restart
sudo ./arclore-deploy/uninstall.sh      # remove (add --purge to wipe data)
```

For Windows editor hosts, `arclore-deploy/install-windows.ps1` installs the
arc-lore-auth TLS certificate into the machine trust store so the UE plugin can verify
the `:8443` gRPC connection.

See each subdirectory's own `README.md` / `INSTALL.md` for full detail.

## License

This unit is licensed under the **European Union Public Licence v. 1.2 (EUPL-1.2)** —
see [`LICENSE`](LICENSE). The license file is mirrored to the public repo root alongside
the three subdirectories.

## Related

- Mirror wrapper: [`../git-mirror/mirror-arclore.ps1`](../git-mirror/mirror-arclore.ps1)
- Public mirror: <https://github.com/iniside/ArcLore>
