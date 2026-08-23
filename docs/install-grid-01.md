# Install Loom on grid-01

Host: ReliableSite bare metal `104.238.222.91` (`grid-01.grogan.dev`). 32 threads, 187GiB RAM, 3.5T ZFS. **Loom is the tenant of this box.** Grid and Incus have been removed.

## What is running (2026-08-23)

- Image `loom:local` as container `loomd`, `127.0.0.1:8080`
- `loom-surreal` on internal docker network `loom-control` (`surrealkv:/data`, user `loom`)
- Host systemd Caddy owns 80/443. `grogan.dev`, `loom.grogan.dev`, and `*.preview.grogan.dev` reverse-proxy to `127.0.0.1:8080`
- Secrets: `/etc/loom/env` (mode 0600). Do not commit.
- Data: docker volume `loom-data` → `/data/loom` in the container
- Source checkout for rebuilds: `/srv/loom`

## Ports

Do **not** run a second Caddy in compose on this host. Host Caddy already terminates TLS.

## Disk

- Docker graph: host docker (currently `/var/lib/docker` on `/`)
- Loom CAS: volume `loom-data`
- Surreal: volume `loom-surreal`
- ZFS pool name is still `grid` (host disks). Incus/workstation datasets are gone. Optional old snapshot: `grid/backup/loom-data` — not in the live path. Do not `zpool destroy grid`.

## Rebuild / restart

```bash
rsync -az --delete --exclude target --exclude .git \
  ./ grid-01:/srv/loom/
ssh grid-01 'cd /srv/loom && docker build -t loom:local . && docker rm -f loomd && \
  docker run -d --name loomd --restart unless-stopped \
    --network loom-apps --network loom-control \
    -p 127.0.0.1:8080:8080 --env-file /etc/loom/env \
    -v loom-data:/data/loom loom:local'
```

`docker compose` is **not** installed on this host (Docker 26.1.5 without the compose plugin). `docker-compose.yml` is the intended layout; runtime is `docker run` until the plugin is installed.

Required env in `/etc/loom/env`: `LOOM_TOKEN`, `LOOM_DEPLOY_TOKEN`, `LOOM_SECRETS_KEY`, `SURREAL_PASS`, `SURREAL_USER=loom`, `LOOM_BASE_DOMAIN=apps.grogan.dev`.

Do not mount `docker.sock` into loomd until image build/smoke exists.

## Smoke

```bash
curl -fsS https://loom.grogan.dev/healthz
# unauth /status → 401
# owner bearer /status → 200
# GET /v1/repos → []
```

Local CLI: `~/.config/loom/credentials` with `LOOM_URL=https://loom.grogan.dev` and the owner token.

## Cutover

Greenfield. `loom repo import` existing remotes. Do not migrate the old Incus backup at `grid/backup/loom-data` into this volume.
