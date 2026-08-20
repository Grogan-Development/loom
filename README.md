# Loom

Standalone smart repository: content-addressed source, feature contracts instead of pull requests, and lightning CI. Rust, one Docker image, no Nero / Grid / Restate / Kiln / Identity sidecar.

Git is a compatibility gateway. Protected refs move only through atomic compare-and-swap after CI evidence.

## What this is

Modern Loom is the Grid `crates/loom` kernel (CAS, refs, graphs, native source, Git HTTP/SSH/hooks) extracted from Grogan Grid. Feature contracts and CI used to live in `grid-api` + Nero Restate. They are first-class Loom now.

Older Loom (Grogan-Foundry, USB ColdArchive) was a Surreal/S3/Git product. This tree does not import that code.

**Stripped:** `grid-nero`, Restate, Cedar/PASETO Identity, Kiln Incus workspaces, Relay model routes, `git.grogan.dev`, Data-VM loopback-only binds, Surreal feature records.

**Kept:** immutable CAS, protected-ref CAS + rollback, candidate verify, software graphs, Git workspace/candidate branches, native source commit/materialize.

**Absorbed:** two-gate features (draft → approve → CI candidate → accept/reject) and digest-cached test runs.

## API

Unauthenticated:

- `GET /healthz`

Bearer token on everything else (`Authorization: Bearer $LOOM_TOKEN`):

| Method | Path | Role |
| --- | --- | --- |
| GET | `/loom/v1/health` | CAS ready |
| POST | `/loom/v1/source/commit` | native source mutation |
| POST | `/loom/v1/source/materialize` | reconstruct a revision |
| POST | `/loom/v1/candidates/verify` | heads reachable, protected ref still at base |
| POST | `/loom/v1/refs/cas` | atomic multi-repo promotion |
| POST | `/loom/v1/graphs/ingest` | pin a software graph |
| POST | `/loom/v1/graphs/read` | read a graph |
| POST | `/v1/features` | create a feature (PR replacement) |
| POST | `/v1/features/{id}/approve` | Gate 1 |
| POST | `/v1/features/{id}/candidates` | run lightning CI, attach candidate |
| POST | `/v1/features/{id}/accept` | Gate 2 + protected-ref CAS |
| POST | `/v1/features/{id}/reject` | keep candidate, do not promote |
| `*` | `/git/{repo}.git/…` | Smart HTTP. Push only `refs/heads/workspaces/*` and `refs/heads/candidates/*` |

## Feature flow

1. Commit a base revision and create `refs/main`.
2. `POST /v1/features` with title, scenarios, and `target_ref` (usually `refs/main`).
3. `POST /v1/features/{id}/approve`.
4. Land work as a native source commit or a Git push to `refs/heads/candidates/{id}`.
5. `POST /v1/features/{id}/candidates` with base + head. Loom verifies CAS readiness, materializes, runs CI, caches by source digest.
6. `POST /v1/features/{id}/accept` promotes protected refs atomically and stores the reverse CAS.

CI reads `loom-ci.toml` in the candidate tree:

```toml
[ci]
timeout_seconds = 120
commands = [["cargo", "test", "--offline", "--quiet"]]
```

If that file is absent: `Cargo.toml` → `cargo test --offline`, `package.json` → `npm test`, otherwise a non-empty tree check.

## Docker (bare metal)

```bash
export LOOM_TOKEN="replace-me"
docker compose up --build -d
```

Data lives in the `loom-data` volume (`/data/loom` in the container). Put a reverse proxy in front for TLS.

```bash
docker run --rm \
  -e LOOM_TOKEN=replace-me \
  -p 8080:8080 \
  -v /srv/loom:/data/loom \
  loom:local
```

## Build

```bash
cargo test --locked -p loom
cargo build --release -p loom
```

Binaries: `loom` (server) and `loom-git-hook` (pre-receive).
