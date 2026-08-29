# Loom

Standalone smart repository: content-addressed source, feature contracts instead of pull requests, lightning CI.

Git is a compatibility gateway. Protected refs move only through atomic compare-and-swap after CI evidence.

## What this is

Loom is the source of truth for code, refs, features, evidence, and events. Other products are git customers of Loom, not compute, review, or CD backends.

**Kept:** immutable CAS, protected-ref CAS + rollback, candidate verify, software graphs, Git workspace/candidate branches, native source commit/materialize, two-gate features, digest-cached CI, outbound git mirror, evidence-gated deploy scripts.

**Removed:** the agent console, chat, memory, skills, onboarding/grill, model matrix, plans, workspaces, docker apps-server, maintain bot, Grid review dispatch, outbound webhooks, MCP surface, secrets store.

Older Grogan-Foundry Loom and the Grid×Nero×Loom trio contract live in [`docs/archive/`](docs/archive/). Current intent: [`docs/intent.md`](docs/intent.md).

## API

Unauthenticated:

- `GET /healthz`

Owner bearer (`Authorization: Bearer $LOOM_TOKEN`) — features, CAS RPC, Git, `POST /v1/releases/{repo}/ci`, evidence GET, catalog, projects, tokens, bootstrap.

Scoped tokens (`POST /v1/tokens`): perms `git`, `features`, `evidence`, `review`, `events`. Product Gate 1/2 stay owner-only.

Deploy-only bearer (`Authorization: Bearer $LOOM_DEPLOY_TOKEN`) — `POST /v1/releases/{repo}/{oid}/deploy`. The owner token is rejected on this route.

Repository names are `project/repo` (`billing/api`). Git Smart HTTP: `/git/{repo}.git/…` (percent-encode `/` as `%2F`). Push only `refs/heads/workspaces/*` and `refs/heads/candidates/*`.

## Feature flow

1. Import or commit a base revision and bootstrap `refs/main`.
2. `POST /v1/features` with title, scenarios, and `target_ref` (usually `refs/main`).
3. Owner `POST /v1/features/{id}/approve`.
4. Land work as a native source commit or a Git push to `refs/heads/candidates/{id}`.
5. `POST /v1/features/{id}/candidates` with base + head. Loom verifies, materializes, runs CI, caches by source digest.
6. Owner `POST /v1/features/{id}/accept` promotes protected refs atomically and queues an outbound mirror push.

CI reads `loom-ci.toml` in the candidate tree. Humans run the same non-deploy pipeline with `./scripts/ci.sh`.

## Docker

```bash
export LOOM_TOKEN="replace-me"
docker compose up --build -d
```

The server binary is `loomd`. The CLI binary is `loom`. Data lives in the `loom-data` volume (`/data/loom`). Caddy terminates TLS in front; only the control plane is routed (`loom.grogan.dev` → `loomd:8080`).

## Build

```bash
./scripts/ci.sh
cargo build --release -p loom -p loom-cli
```

Binaries: `loomd` (server), `loom-git-hook` (pre-receive), `loom-insights` (offline tree analysis), `loom` (CLI).
