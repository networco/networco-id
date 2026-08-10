---
name: ship
description: Take a code change to test and then production for networco-app or networco-id, with an agent review gate and synced test/prod versioning. Phase A (ship a change) — branch + local checks, commit/push, open PR, run an agent code-review that comments on the PR, act on the findings, then auto-merge to main on a clean review + green CI and delete branches. Phase B ("release to test") — cut an rc pre-release (vX.Y.Z-rc.N) that deploys that exact version to test. Phase C ("release to prod") — promote the tested rc to a full release vX.Y.Z, so test and prod stay in lockstep; if test was never bumped, infer the semver bump from the diff. Use when the user says "ship this", "run the full flow", "release to test", "release to prod", "patch/minor/major release to test", or asks to review-merge or promote a version. Pauses only before cutting a prod release.
---

# Ship → test → prod (with review + synced versioning)

Three phases for getting a change from a working tree to live in prod, for **networco-app** (`networco/networco`) or **networco-id** (`networco/networco-id`). Run the phase the user asks for.

**Versioning model (both repos):** an **rc pre-release** `vX.Y.Z-rc.N` deploys that exact version to **test**; a **full release** `vX.Y.Z` deploys to **prod**. Prod reuses the version that was on test → test and prod stay in sync. Wired via GitHub release event types: `prereleased` → `deploy-test.yml`, `released` → `release.yml`.

---

## Phase A — ship a change (PR → review → auto-merge)

1. **Branch from up-to-date main**:
   ```bash
   git checkout main && git pull --ff-only origin main && git checkout -b <type>/<slug>
   ```
2. **Local gate** (must be clean): web/TS → `pnpm type-check` + `pnpm lint` (0 errors) + `pnpm test`; .NET → `dotnet build` + `dotnet test`; Go → `go build ./...` (+ `go vet`).
3. **Commit** (conventional; **no `Co-Authored-By` trailer and no generated-with line** — anywhere, including PR bodies and release notes), **push**, **open PR** (`gh pr create`, body links the issue/comment with **`Refs #N`** — *not* `Closes/Fixes` (see step 8)).
4. **Wait for CI green** — CI runs **once** per push (the `pull_request` trigger only; see the CI-runs note in Gotchas). Watch that single run, then check the PR rollup has no `incomplete`/`failed`.
5. **Agent review — comment on the PR.** Run the `code-review` skill against the PR diff and post findings as inline PR comments:
   ```
   /code-review --comment
   ```
6. **Act on the review.** Read the findings; for each actionable one, **fix in code + push** (CI re-runs) or reply on the thread why it doesn't apply; resolve the threads. Re-review if the changes were substantial. The review is "clean" when no actionable findings remain unresolved.
7. **Auto-merge on clean review + green CI** (no prompt — this is the agreed gate):
   ```bash
   gh pr merge <n> --repo <repo> --squash --delete-branch
   git checkout main && git branch -D <branch> && git fetch --prune origin && git pull --ff-only origin main
   ```
8. **Hand the issue back — do NOT close it.** Resolved issues go back to the reporter for verification, not closed by us:
   - In the PR body, **avoid GitHub closing keywords** (`Closes #N`, `Fixes #N`, `Resolves #N`) — they auto-close the issue on merge. Use **`Refs #N`** / **`Addresses #N`** instead.
   - After merge: reassign the issue to its **reporter** and add the **`Review`** label, leaving it **open** (the reporter closes it once verified):
     ```bash
     reporter=$(gh issue view <n> --repo <repo> --json author --jq '.author.login')
     gh issue edit <n> --repo <repo> --add-label Review --add-assignee "$reporter"
     ```
   - Post a short **Norwegian comment** on the issue — what changed and that it's on the way.

> Auto-merge is for **feature/content** PRs. A PR that changes CI workflows, this skill, or other infra is **not** auto-merged — surface it for human review.

Merging to `main` does **NOT** deploy to test anymore — `deploy-test.yml` is gated to rc pre-releases only (the old push-to-main trigger was dropped: it ran a second, redundant test deploy per change that doubled Actions usage and raced the rc deploy on the migration job). **The only way to get a change on test is Phase B (cut an rc).** Every prod release is then promoted from that `vX.Y.Z-rc.N` — never skip Phase B and jump straight to a full release.

---

## Phase B — "release to test" (cut an rc → versioned test deploy)

1. **Pick the bump.** If the user said patch/minor/major, use it. If they just said "release to test", **infer from the merged diff since the last prod release** (see *Semver inference*).
2. **Compute the candidate version** from the last **full** release:
   ```bash
   gh release list --repo <repo> --exclude-pre-releases --limit 1   # e.g. v0.49.7
   ```
   patch → `v0.49.8`, minor → `v0.50.0`, major → `v1.0.0`.
3. **Pick the rc number** — next `-rc.N` for that version (rc.1 if none exist yet):
   ```bash
   gh release list --repo <repo> | grep 'vX.Y.Z-rc'   # highest N → N+1
   ```
4. **Create the rc pre-release** (triggers `deploy-test.yml` at that exact version):
   ```bash
   gh release create vX.Y.Z-rc.N --repo <repo> --prerelease --target main --title "…" --notes "…"
   ```
   **`--prerelease` is non-negotiable** — without it the rc routes to prod (`release.yml`) instead of test *and* GitHub marks it `latest`, which is wrong (only full `vX.Y.Z` is latest). Immediately verify (`isLatest` only exists on `release list`, NOT `release view`):
   ```bash
   gh release list --repo <repo> --json tagName,isPrerelease,isLatest --jq '.[] | select(.tagName=="vX.Y.Z-rc.N")'   # expect isPrerelease=true, isLatest=false
   ```
5. **Verify test.** Watch the `deploy-test.yml` run for the release event; confirm the repo's **health line** (table) — not just `conclusion=success`.

State the version you cut, e.g. "Test is now on **0.50.0-rc.1**."

---

## Phase C — "release to prod" (promote the tested version)

1. **Find the version to ship.** The most recent rc pre-release since the last full release:
   ```bash
   gh release list --repo <repo> --limit 10   # newest vX.Y.Z-rc.N after the last full vA.B.C
   ```
   - **rc found** → promote it: the prod version is that rc's `vX.Y.Z` with the `-rc.N` suffix removed (same number).
   - **no rc since last prod** → **do NOT jump straight to a full release.** The rc is the versioned test build prod promotes from, and it's required (it's also the only thing that deploys to test). Go back to **Phase B**, cut the `vX.Y.Z-rc.N` pre-release first (infer the bump from the diff), verify test, then promote.
2. **⏸ Confirm before prod.** State the version and that this deploys to prod; get an explicit OK.
3. **Create the full release** (triggers `release.yml` → prod):
   ```bash
   gh release create vX.Y.Z --repo <repo> --target main --title "vX.Y.Z — …" --notes "…"
   ```
4. **Tidy the rc** (optional): delete the now-promoted rc pre-release(s) so the list stays clean:
   ```bash
   gh release delete vX.Y.Z-rc.N --repo <repo> --cleanup-tag --yes
   ```
5. **Verify prod.** Watch `release.yml`; **re-check** `status=="completed"` (the watcher can return before the Deploy-to-Production job finishes) and re-watch if needed; confirm the prod **health line**.

---

## Semver inference (from the merged diff since the last prod release)

Read the commits / PR titles since the last full release tag and pick:
- **major** — a breaking change (`feat!:`, `BREAKING CHANGE`, removed/renamed public API or contract).
- **minor** — a new feature (`feat:`) with no break.
- **patch** — fixes, copy, chore, refactor, deps (`fix:`/`chore:`/`refactor:`/`style:`/…).

Always **state the chosen bump and the reason** before tagging.

## Per-repo specifics

| | networco-app (`networco/networco`) | networco-id (`networco/networco-id`) |
|---|---|---|
| Local path | `/Users/bisand/dev/networco/networco-app` | `/Users/bisand/dev/networco/networco-id` |
| Local checks | `pnpm type-check` + `pnpm lint` + `pnpm test`; `dotnet test apps/api.tests/…`; `go build` | `dotnet build src/NetworcoId/…` + `dotnet test` |
| Deploy mechanism | `scripts/deploy.sh TEST\|PROD` — **EF migration-job gate**, then rollout | **inline `kubectl`** — `rollout restart` + `rollout status --timeout=180s`; **no migration job** (migrates at startup) |
| Deployments | `networco-api`, `networco-worker`, `networco-web`, `blob` | `networcoid`, `networcoid-worker` |
| Health line | `Deployment of {TEST\|PROD} successful — all rollouts healthy ✓` | `deployment "networcoid" successfully rolled out` (+ `networcoid-worker`) |
| Extra prod step | — | **"Register app redirect URI + audience on the OAuth client"** psql step (targets the CNPG **primary** in `networco-db`; can legitimately log `UPDATE 0`) |
| Version series | `v0.49.x` (as of 2026-06) | `v0.10.x` (as of 2026-06) |

## Gotchas (hard-won)

- **rc → test, full → prod.** The split is the GitHub event type: `prereleased`→`deploy-test.yml`, `released`→`release.yml`. Create rc with `--prerelease`; create prod **without** it. Never `--prerelease` a prod version.
- **An rc must never be GitHub `latest`.** Only full `vX.Y.Z` releases are `latest`. GitHub blocks a prerelease from being latest, so a "latest" rc means it was created *without* `--prerelease` (also wrongly routes to prod). After cutting an rc, verify `isPrerelease=true, isLatest=false`. The model is **kept on purpose** — rc is the promote-the-tested-version-without-re-bumping mechanism.
- **One CI run per push.** `ci.yml` triggers on `pull_request` only (not `push`), with a `cancel-in-progress` concurrency guard — so each push to a PR branch produces exactly one run. Wait for that single run; don't expect a second. A branch with no open PR gets no run until the PR is opened. networco-id runs no PR CI at all (release-triggered only).
- **`gh run watch` can return early on releases.** It has exited 0 while **Deploy to Production** was still running. Re-check `status == "completed"` and re-watch.
- **Health line, not just conclusion.** Grep the rollout log for the repo's health line.
- **Remote delete ≠ local cleanup.** `--delete-branch` removes the remote branch only; still `git branch -D` + `fetch --prune`.
- **Squash-merge** to keep `main` linear (matches every prior `… (#NN)` commit).
- **networco-id read-only-replica bug (fixed).** The prod OAuth-client `UPDATE` once failed with *"cannot execute UPDATE in a read-only transaction"* (hit replica `pg-1`); fixed in `cf0da43` to target the CNPG primary. A green run may still log `UPDATE 0` — pre-existing, not a regression. Use the `networco-cluster` skill for DB access if investigating.
- **EF migrations (app) live in `Networco.Shared`**, not `apps/api`. The Deploy step runs them via `api-migration-job`; watch for `Migration job completed ✓` before the rollout lines.
- **Test deploys are rc-only (both repos).** `deploy-test.yml` triggers on `release: prereleased` only — merging to `main` no longer deploys to test. (Historically it also ran on push:main, doubling Actions usage and racing the rc deploy on `api-migration-job`; that trigger was removed.) Prod versioning uses the release **tag**, so the old push-time VERSION bump on id was safe to drop.

## Notes

- `gh`/`git` run locally and aren't blocked by the prod-write classifier; the **prod release** is the action the confirm gate exists for.
- Don't hand-edit `VERSION` — the workflows manage it.
- For live-cluster investigation use the `networco-cluster` skill.
