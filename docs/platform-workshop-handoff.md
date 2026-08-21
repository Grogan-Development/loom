# Platform workshop and Loom handoff

Status captured: 2026-08-21 15:49 UTC.

This is a continuation document for an agent with no prior chat context. The
platform workshop is partially deployed and **not complete**.

## Intended system

`ws-platform` is the permanent Grid workshop for developing `grid`, `loom`,
`nero`, and future platform services. Every repository uses Loom branch
`workspaces/platform`. A headless factory Nero may author and submit
candidates, but it must never approve, accept, or deploy. Those remain
human/owner actions.

Host `/opt/{grid,loom,nero}` checkouts are deploy-only. Do not continue normal
development there.

## Loom deployment and commits

Deployed Loom revision:

```text
00d60093973fcc755d1aa52bcef1e840db90ecd8
```

Relevant commits on `main`:

- `d11abf5` — supervised platform pipeline, events, review integration
- `5856075` — exact feature/review token binding and review recovery
- `00d6009` — Git Smart HTTP advertises Basic auth to credential helpers

Isolated continuation worktree:

```text
/var/lib/grid/build/bootstrap-loom-auth
branch: bootstrap/git-basic-challenge
```

It is clean and matches `origin/main`.

Loom runs inside the Incus VM `loom` and is healthy. Deployment is:

```sh
/opt/loom/deploy/loom-vm-apply <git-oid>
```

The apply target is isolated under `/var/lib/loom/target`; do not build under
`/opt/loom/target`.

## Git authentication bug fixed

Loom already accepted scoped secrets as:

- `Authorization: Bearer <secret>`
- the password of HTTP Basic

However, unauthorized Git responses advertised only:

```text
WWW-Authenticate: Bearer realm="loom"
```

Git/libcurl therefore never asked the credential helper for its Basic
password. Commit `00d6009` changes only the Git gateway challenge to:

```text
WWW-Authenticate: Basic realm="loom"
```

The server still resolves the password through the same scoped-token
authority. A router-level regression test is in
`crates/loom/tests/tokens.rs`.

## Source bootstrap performed

Loom repositories were empty because previous work existed only on Cursor
Origin. Owner-authenticated Git pushes seeded:

- `grid`: `refs/heads/workspaces/platform`
- `loom`: `refs/heads/workspaces/platform`
- `nero`: `refs/heads/workspaces/platform`

The first push attempted `main` and `workspaces/platform` in one batch. Loom
correctly rejected the entire pre-receive batch because `main` is protected.
The workspace branch was then pushed separately.

Nero's Cursor Origin history cannot be unshallowed (`bad object` / `bad pack
header`). Nero was seeded as a single root snapshot of the deployed tree.

## Critical missing Loom backend

There is no safe owner-facing bootstrap operation to create the initial
protected `refs/main` from an imported Git revision.

This blocks a clean first feature lifecycle because feature bases and
acceptance expect a protected target ref. Do **not** weaken Git writable-ref
validation and do not permit direct pushes to `main`.

Design an explicit, audited, idempotent operation with at least:

- owner authentication only
- repository and imported revision input
- refusal when the protected ref already exists at a different revision
- durable event/audit record
- exact read-back
- support for a snapshot bootstrap when legacy Git history is shallow/grafted
- tests proving normal scoped tokens cannot call it

## Other missing Loom/backend work

1. **Repository/service catalog**
   - Current repository names are effectively hard-coded across Grid/Loom.
   - Future services need typed metadata: protected ref, checkout path, CI
     policy, internal endpoint, deploy target, and factory authority.

2. **Token reconciliation**
   - Grid currently trusts its stored Loom token ID/secret.
   - Add an API/read model that lets Grid confirm the token still exists with
     exact repositories, permissions, bindings, and expiry.
   - Rotation/remint must be auditable and idempotent.

3. **Provisioning readiness**
   - Internal Git should expose health/readiness separately from general Loom
     health.
   - Git clone failures need structured error codes rather than only CGI text.

4. **Factory event contract**
   - Define which event kinds wake the factory, delivery/cursor semantics,
     deduplication, retry, and shutdown behavior.
   - A factory must stop at approve/accept/deploy and record that it is waiting
     for a human.

5. **Review runner lifecycle**
   - Exact feature/review token binding is implemented.
   - Still verify expiry, cancellation, restart recovery, result idempotency,
     and token revocation against a real Grid runner.

6. **Deploy authority**
   - Keep deploy-token and owner-token boundaries separate.
   - Add end-to-end evidence that a factory/workspace token cannot invoke any
     release deployment route.

7. **Origin demotion**
   - Origin webhooks are currently logged as ignored in mirror-only mode.
   - Document and test the one-time migration/import path, then keep Origin as
     mirror/backup only.

## Current cross-system state

At capture time:

- Grid, Loom, and Nero services are deployed.
- `ws-platform` is running with active ACP/factory/GC units.
- Only the `loom` guest checkout is valid on `workspaces/platform`.
- `grid` and `nero` guest directories are unborn checkouts and still require
  successful provisioning recovery.
- Grid uses internal Loom URL `http://10.76.0.15:8080`.
- A scoped `ws-platform` token exists with repositories
  `grid,loom,nero` and permissions `git,features,evidence,events`.
- Never record either owner or scoped secret values.

## Validation commands

```sh
# Loom VM deployment/health
incus exec --project grid-trusted loom -- sh -c \
  'systemctl is-active loom; cat /var/lib/loom/applied-oid'

# Scoped CI from the isolated worktree
cd /var/lib/grid/build/bootstrap-loom-auth
CARGO_TARGET_DIR=/var/lib/grid/build/loom-ci-target ./scripts/ci.sh

# Recent Loom logs
incus exec --project grid-trusted loom -- \
  journalctl -u loom --since "10 minutes ago" --no-pager
```

Do not resume Loom feature development in `/opt/loom`.
