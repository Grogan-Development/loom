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

Origin webhook (Origin App signatures, not a bearer token):

- `POST /v1/origin/webhook`

Owner bearer (`Authorization: Bearer $LOOM_TOKEN`) — features, CAS RPC, Git, `POST /v1/releases/{repo}/ci`, and evidence GET. `{repo}` is `loom`, `nero`, or `grid` (not `grogan-dev/…`). `{oid}` is a lowercase hex SHA (7–64 chars).

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
| POST | `/v1/releases/{repo}/ci` | clone Origin SHA, run `loom-ci.toml` |
| GET | `/v1/releases/{repo}/{oid}` | evidence `{ status, tests_passed, job_id, log, origin_check_id }` |
| `*` | `/git/{repo}.git/…` | Smart HTTP. Push only `refs/heads/workspaces/*` and `refs/heads/candidates/*` |

Deploy-only bearer (`Authorization: Bearer $LOOM_DEPLOY_TOKEN`). The owner token is **rejected** on this route:

| Method | Path | Role |
| --- | --- | --- |
| POST | `/v1/releases/{repo}/{oid}/deploy` | fail-closed apply; empty body. `409 origin.deploy_blocked` unless `tests_passed` for that SHA |

## Feature flow

1. Commit a base revision and create `refs/main`.
2. `POST /v1/features` with title, scenarios, and `target_ref` (usually `refs/main`).
3. `POST /v1/features/{id}/approve`.
4. Land work as a native source commit or a Git push to `refs/heads/candidates/{id}`.
5. `POST /v1/features/{id}/candidates` with base + head. Loom verifies CAS readiness, materializes, runs CI, caches by source digest.
6. `POST /v1/features/{id}/accept` promotes protected refs atomically and stores the reverse CAS.

CI reads `loom-ci.toml` in the candidate tree. Humans run the same non-deploy pipeline with `./scripts/ci.sh` (`cargo fmt --check`, `clippy -p loom -D warnings`, `test -p loom`; ~10 min; no Docker, no service restart):

```toml
[ci]
timeout_seconds = 600
commands = [
  ["cargo", "fmt", "--check"],
  ["cargo", "clippy", "--locked", "-p", "loom", "--", "-D", "warnings"],
  ["cargo", "test", "--locked", "-p", "loom"],
]
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

## Automations

Cursor Cloud is CD only: after an Origin merge or push to `main`, an agent may read Loom evidence and POST deploy. It must not compile, SSH, or merge. Loom is the CI runner.

Create **one Cursor Automation per Origin repo** (`grogan-dev/loom`, `grogan-dev/nero`, `grogan-dev/grid`). Paste the prompt from [`deploy/cloud-cd-prompt.md`](deploy/cloud-cd-prompt.md). Tools: comment on PRs. Secrets: `LOOM_TOKEN` (GET evidence) and `LOOM_DEPLOY_TOKEN` (POST deploy only). HTTPS to `https://loom.grogan.dev` — no MCP.

Self-deploy caveat: applying `loom` restarts the Loom service under the in-flight deploy request, so the first POST may return `409 origin.deploy_failed`. The host runs the apply in a transient systemd unit ([`deploy/loom-vm-apply`](deploy/loom-vm-apply), installed at `/usr/local/sbin/loom-vm-apply` on grid-01), so it finishes anyway; a single retry ~30 s later returns 200.

**To finish in Automations editor:** pick the Origin repo, add both secrets, enable PR comments, set triggers to pull request merged **and** push to `main`, paste the matching prompt, save. Do not open the editor from chat until that draft is approved.

**Origin UI (cannot be done from git):**

1. Register an Origin App at [codebase app settings](https://cursor.com/codebase/settings/apps). Install it on `grogan-dev` for `loom`, `nero`, and `grid`.
2. Webhook URL: `https://loom.grogan.dev/v1/origin/webhook` (Origin App signatures; not `LOOM_TOKEN`).
3. Each repo **Settings → Rules and Protections**: require the **Loom** check (`suiteKey` `loom`, check key `ci`) before merge.
4. `loom.grogan.dev` may still be Railway until Cloudflare login completes. Webhooks and Cloud CD need the VM once DNS is cut over; do not block drafting on DNS.

## Build

```bash
cargo test --locked -p loom
cargo build --release -p loom
```

Binaries: `loom` (server) and `loom-git-hook` (pre-receive).
