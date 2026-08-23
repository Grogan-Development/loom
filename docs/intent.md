# Loom intent

Status: kernel + JSON control-plane **records**. Onboarding, jobs, host runners, live apps-server, and the maintain agent are **not** implemented. Trio contract: [`archive/platform.md`](archive/platform.md).

Loom is the source of truth. A private GitHub org (`loomnero`, name is arbitrary) is an offsite mirror only — in case this box dies. Not a second workflow. Not GitHub PRs.

## Locked product

Git provider + CI that actually runs + apps-server for apps/services + job runner that can target that apps-server **or** a dedicated host + onboarding that locks intent before any rewrite.

- Disconnect = decouple. No Grid, no Incus, no Cursor Origin as SoT or CD. HTTP `Runner` is a trait. Nero is a **harness pattern** and live products (`nero/assistant`, `nero/chat`), not the discarded Grid agent.
- Work items = **features**, not PRs. A **plan** is a DAG of features. Owner accepts the plan; agents cannot skip nodes.
- Product features: owner Gate 1 and Gate 2. Scheduler-created `class=maintenance` is born approved. `maintain` accepts only that class. Coding agents stay `git`+`features` on `candidates/*`.
- **Apps-server** (this host): apps, services, and temp pre-flight previews. Not TZP Minecraft.
- **Dedicated host**: registered machine with a pull `loom-runner`. TZP Minecraft stays on OVH. Owner does not SSH. Loom jobs replace GitHub Actions / `bbovh`.
- Agents may deploy only to **pre-flight** (apps-server preview, or `host:<id>` / `dev`). Live is owner-only.
- Names: `project/repo`. Not GitHub orgs as identity.
- Events JSONL is audit truth. Surreal is a sibling for a later graph projection, not the control store yet.

## Onboarding (next to build)

No coding agent on a project until intent is locked. That is how slop stops eating tokens.

1. Admit bytes: empty import + `git push`, bootstrap `refs/main`. Pack detect. No rewrite.
2. Classify (automatic, grill can override): `working` | `messy` | `slop` | `abandoned` | `empty`.
3. Intent draft on the control plane (not a rewritten README).
4. HITL grill, **project**-scoped. `working` = short confirm. Messy = exact ideas. Slop/abandoned/empty = epitaph unless revived.
5. Plan DAG. Ingest existing backlogs (TZP `L####` and friends) so slices **target** them. Done items stay historical.
6. CI bot (`maintain` / subclass `ci`) writes `loom-ci.toml` and pre-flight recipes. Humans do not maintain CI.
7. Slices on `candidates/*`: lightning CI + insights (LSP + software graph). Evidence must not get worse.
8. Pre-flight env only for agents. Owner promote to live (apps-server or dedicated host).

Calibration: TZP is `working` (runnable evidence, not scaffold). Empty `printpathfinders` is `empty`. Stale marketing trees are `messy` or `slop`.

## Compute

| Plane | For | Examples |
| --- | --- | --- |
| Apps-server | Apps, services, temp preview | `tzp/web` after Railway cutover, `grogan/www`, Nero API |
| Dedicated host | Boxes that stay boxes | TZP Minecraft on OVH (`dev` + `live`) |
| Loom jobs | CI / pre-flight / apply on either plane | CI bot emits; `loom-runner` pulls on a host |

`tzp/launcher` is a client (no host). `tzp/web` leaves Railway for the apps-server. Minecraft live/dev stay on `tzp-ovh`. Do not stand up a second Minecraft on grid-01.

## This tree (honest)

**Present:** CAS, protected-ref CAS, native source, Git gateway, two-gate features, digest-cached local CI (`LocalProcessRunner`), tokens including `maintain`, events, insights, reviews. Empty catalog. `project/repo` names. JSON `control.json` (projects, app records, maintain queue, webhooks). `secrets.json`. Import (https or empty). Search/compare/tree/blob. Pack detect. App promote/rollback **records**. Owner dashboard. Backup. MCP **list** (POST is 501). CLI verbs. Compose: caddy + surreal + loomd.

**Absent:** classify / intent grill / Plan object. `loom-runner` / host registry / job dispatch. Docker image build/smoke (`ImageMissing`). Real app processes. Planner loop. GitHub mirror push. MCP execution.

Origin/Grid flags still exist on `loomd`. They are leftover, not the product.

## First fleet

Empty import + push from a laptop (no GitHub token on the host). Closed loop after land: one feature accept on `loom/loom`. Then build onboarding before any repair agents.

| Project | Repo | Source |
| --- | --- | --- |
| `loom` | `loom` | this tree |
| `grogan` | `www` | `Grogan-Development/grogan.dev` |
| `gachagang` | `www` | `Grogan-Development/gachagang.com` |
| `printprecision` | `app` | `print-precision-beta` |
| `printprecision` | `pathfinders` | `printpathfinders.com` (empty) |
| `nero` | `assistant` | `Grogan-Development/nero` |
| `nero` | `chat` | `Grogan-Development/chatnero.com` |
| `tracedb` | `engine` | `Trace-DB/tracedb` |
| `tracedb` | `www` | `Trace-DB/trace-db.com` |
| `tzp` | `core` | `bloodbath-core` |
| `tzp` | `pack` | `bloodbath-pack` |
| `tzp` | `server` | `bloodbath-server` |
| `tzp` | `infra` | `bloodbath-infra` |
| `tzp` | `web` | `tzp-web` |
| `tzp` | `launcher` | `tzp-launcher` |

## Names (do not collide)

- **Insights** — digest-cached LSP + software-graph analysis on a candidate.
- **Onboarding** — first-run classify + intent + grill.
- **Pre-flight env** — AI test server (`apps-server` preview or `host:<id>` / `dev`).
- **Loom jobs** — GH Actions replacement. Not `.github/workflows` as source of truth.
- **Nero** — harness pattern + the `nero/*` products. Not Grid’s coding agent.
