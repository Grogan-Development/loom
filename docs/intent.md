# Loom intent

Status: advanced git / repo setup. CAS source of truth, Git smart-HTTP gateway, two-gate feature contracts, lightning CI, outbound GitHub mirror, evidence-gated deploys. Trio contract: [`archive/platform.md`](archive/platform.md).

Loom is the source of truth. A private GitHub org is an offsite mirror only — in case this box dies. Not a second workflow. Not GitHub PRs.

## Locked product

Git provider + CI that actually runs. Nothing else.

- Work items = **features**, not PRs. Owner Gate 1 (approve) and Gate 2 (accept). Accept promotes protected refs atomically after CI evidence, with an exact rollback CAS.
- CI is local and digest-cached (`LocalProcessRunner`); it reads `loom-ci.toml` from the candidate tree. Insights (diff, symbols, blast radius) run pre-flight after CI.
- Reviews are records with findings and suggested patches; a policy may make an approved review blocking.
- Names: `project/repo`. Not GitHub orgs as identity.
- Events JSONL is audit truth.
- GitHub is an outbound mirror (`origin.rs`): release records, check-run evidence, mirror push, evidence-gated apply scripts.

## Removed (on purpose)

Agent console and chat, memory, skills, model matrix, plans, onboarding/grill, workspaces, docker apps-server, maintain bot, Grid review dispatch, `loom-runner` host jobs, outbound webhooks, MCP surface, project secrets. The pre-strip tree lives on branch `drift/agent-console`.

## This tree (honest)

**Present:** CAS, protected-ref CAS, native source, Git gateway + pre-receive hook, two-gate features, digest-cached local CI, insights, reviews, tokens, events, projects (`projects.json`), catalog + import (https or empty), search/compare/tree/blob, backup, origin mirror + release CI + evidence-gated deploy. CLI verbs: events, feature, candidate, evidence, insights, review, comment, status, login, repo, project, backup. Compose: caddy + loomd.

**Absent:** anything agent-shaped. Remote CI runners. If a feature is needed later, it gets designed against this kernel, not bolted on.

## First fleet

Empty import + push from a laptop (no GitHub token on the host). Closed loop after land: one feature accept on `loom/loom`.

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
