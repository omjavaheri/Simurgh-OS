# Contributing

## Starting work: file an issue, get a branch for free

Open a GitHub Issue for whatever you're about to do, and label it:

| Label | For | Branch prefix |
|---|---|---|
| `enhancement` (or `feature`) | a new capability or subsystem piece | `feature/` |
| `bug` (or `fix`) | an ordinary bug fix | `fix/` |
| `hotfix` (or `urgent`/`critical`) | an urgent fix (e.g. a broken `main`) | `hotfix/` |

The moment a matching label lands on the issue, `.github/workflows/
branch-from-issue.yml` automatically creates `<prefix>/<issue-number>-
<slugified-title>` off `main` and comments the branch name back on the
issue — e.g. issue #12 "riscv64 Compositor spawn fault" labeled `bug`
becomes `fix/12-riscv64-compositor-spawn-fault`. (Restricted to the
repository owner/collaborators labeling the issue — this repo is
public, so an outside label alone doesn't trigger it.) Check that
branch out and work on it; no one hand-invents branch names.

If you'd rather not file an issue first, you can still create a branch
by hand — just match the same `feature/`/`fix/`/`hotfix/` naming so it
reads consistently in the branch list and PR history.

**No one — including the repository owner — pushes directly to `main`,
ever, not even for a one-line typo fix.** Branch protection has "Include
administrators" turned on specifically so this holds without exception.
Every change reaches `main` only through a pull request.

## Pull requests and merging

1. Open a PR from your branch into `main`.
2. The **CI** workflow (`.github/workflows/ci.yml`) runs automatically:
   host build + test, a per-architecture cross-build matrix, and QEMU
   boot/fault-isolation tests for x86_64/aarch64/riscv64.
3. The PR requires an **approving review from the repository owner**
   — the sole reviewer this project has, enforced by `.github/
   CODEOWNERS` (`* @omjavaheri`) — before the "Merge" button is
   available at all. This needs this repo's own branch-protection
   settings turned on (Settings → Branches → `main`: "Require a pull
   request before merging", "Require approvals" (≥1), "Require review
   from Code Owners", "Require status checks to pass before merging"
   with the CI job(s) selected, "Include administrators", "Do not allow
   bypassing the above settings"). These are GitHub repository
   settings, not something a file in this repo can enforce on its own —
   CODEOWNERS only takes effect once the branch protection rule
   requiring it is turned on.
4. Once approved and merged, the branch is deleted automatically
   (Settings → General → Pull Requests → "Automatically delete head
   branches") and the **Release** workflow (`.github/workflows/
   release.yml`) runs: it waits for CI to report success on the new
   `main` commit, then tags and publishes a new GitHub Release,
   auto-incrementing the `PATCH` version (`v0.1.0` → `v0.1.1` → …) from
   the latest existing tag. A `MINOR`/`MAJOR` bump is a manual `git
   tag` — the next automatic release continues incrementing `PATCH`
   from whatever tag is latest.

In short: **issue + label → branch (auto) → PR → CI → owner approval →
merge → branch deleted → automatic release.** No step is skippable by
design.

Write `Closes #<issue-number>` in the PR description so merging it also
closes the issue automatically — this is a native GitHub behavior, not
something a workflow needs to implement.

## Issue lifecycle

`.github/workflows/issue-lifecycle.yml` handles two related edges:

- **Closed issues are locked immediately** (closest available
  approximation to "closed issues stay as a permanent record" — GitHub
  has no way to make an issue truly unreopenable, not even by the
  repository owner; locking only restricts further comments/reopening,
  it does not forbid it outright).
- **A deleted issue's own auto-created branch is deleted too** —
  "Automatically delete head branches" only fires on a PR merge, so an
  issue removed before its branch ever reached a PR would otherwise
  leave that branch behind forever. The workflow searches all three
  `feature/<N>-`/`fix/<N>-`/`hotfix/<N>-` prefixes for the deleted
  issue's number and removes whatever it finds. If that branch still
  had an open PR, deleting it also closes that PR (GitHub's own normal
  behavior when a PR's head branch disappears).

## Local setup: catch a `main` commit before you even try to push

GitHub's branch-protection ruleset on `main` only controls the server
side (a rejected `push`) — it cannot stop a *local* commit made
directly on your own local `main` branch, since git is distributed and
no server is involved in `git commit`. Point git at this repo's tracked
hooks once per clone to catch that locally too, immediately, instead of
only at push time:

```bash
git config core.hooksPath .githooks
```

`.githooks/pre-commit` then refuses any commit made while on `main`,
with a pointer back to the issue → branch → PR flow above.

## Everything else

See `CLAUDE.md` (local, not checked into this repository) for coding
conventions, architecture references, and the commit-prefix discipline
(`scaffold:`/`feat:`/`fix:`/`docs:`/`refactor:`/`test:`) this project
follows.
