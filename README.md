# Loom

Standalone smart repository: content-addressed source, feature contracts instead of pull requests, lightning CI, and (in later phases) a container apps-server plus an autonomous maintainer for old JS/TS/Python/Go/Rust.

Git is a compatibility gateway. Protected refs move only through atomic compare-and-swap after CI evidence.

## What this is

Loom is the source of truth for code, refs, features, evidence, and events. It does not require Grid, Cursor Origin, or Incus. Other products are git customers of Loom, not compute, review, or CD backends. Nero is a harness pattern and live products in the catalog, not this host's agent.

Older Grogan-Foundry Loom and the Grid×Nero×Loom trio contract live in [`docs/archive/`](docs/archive/). Current intent: [`docs/intent.md`](docs/intent.md).

**Kept:** immutable CAS, protected-ref CAS + rollback, candidate verify, software graphs, Git workspace/candidate branches, native source commit/materialize, two-gate features, digest-cached CI.

**Disconnected:** seeded `grid`/`nero`/`console` catalog, Grid CI/review as the default path, Origin Cloud CD as the deploy orchestrator.

## API

Unauthenticated:

- `GET /healthz`

Owner bearer (`Authorization: Bearer $LOOM_TOKEN`) — features, CAS RPC, Git, `POST /v1/releases/{repo}/ci`, evidence GET, catalog, tokens, bootstrap.

Scoped tokens (`POST /v1/tokens`): perms `git`, `features`, `evidence`, `review`, `events`, `maintain`. `maintain` may accept `class=maintenance` features only. Product Gate 1/2 stay owner-only.

Deploy-only bearer (`Authorization: Bearer $LOOM_DEPLOY_TOKEN`) — `POST /v1/releases/{repo}/{oid}/deploy`. The owner token is rejected on this route.

Repository names are a legacy identifier (`demo`) or `project/repo` (`billing/api`). Git Smart HTTP: `/git/{repo}.git/…` (percent-encode `/` as `%2F`). Push only `refs/heads/workspaces/*` and `refs/heads/candidates/*`.

## Feature flow

1. Import or commit a base revision and bootstrap `refs/main`.
2. `POST /v1/features` with title, scenarios, and `target_ref` (usually `refs/main`). HTTP cannot set `class=maintenance`.
3. Owner `POST /v1/features/{id}/approve`.
4. Land work as a native source commit or a Git push to `refs/heads/candidates/{id}`.
5. `POST /v1/features/{id}/candidates` with base + head. Loom verifies, materializes, runs CI, caches by source digest.
6. Owner `POST /v1/features/{id}/accept` promotes protected refs atomically.

Scheduler-created maintenance features are born approved. A `maintain` token may accept those after evidence; it cannot accept product features.

CI reads `loom-ci.toml` in the candidate tree. Humans run the same non-deploy pipeline with `./scripts/ci.sh`.

## Docker

```bash
export LOOM_TOKEN="replace-me"
export SURREAL_PASS="replace-me"
docker compose up --build -d
```

The server binary is `loomd`. The CLI binary is `loom` (`loom mcp` prints the tool list; HTTP MCP calls are 501). Data lives in the `loom-data` volume (`/data/loom`). Put a reverse proxy in front for TLS. `SURREAL_PASS` is required even though Surreal is not the control-plane store yet.

## Build

```bash
./scripts/ci.sh
cargo build --release -p loom -p loom-cli
```

Binaries: `loomd` (server), `loom-git-hook` (pre-receive), `loom` (CLI).
