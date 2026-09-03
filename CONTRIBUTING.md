# Contributing

## Branch naming

Every change gets its own branch off `main`, named by what kind of change
it is:

| Prefix | For | Example |
|---|---|---|
| `feature/` | a new capability or subsystem piece | `feature/vfs-symlink-support` |
| `fix/` | an ordinary bug fix | `fix/riscv64-compositor-spawn-fault` |
| `hotfix/` | an urgent fix (e.g. a broken `main`) | `hotfix/ci-yaml-syntax` |

No one — including the repository owner — pushes directly to `main`.
Every change reaches `main` only through a pull request.

## Pull requests and merging

1. Open a PR from your branch into `main`.
2. The **CI** workflow (`.github/workflows/ci.yml`) runs automatically:
   host build + test, a per-architecture cross-build matrix, and QEMU
   boot/fault-isolation tests for x86_64/aarch64/riscv64.
3. The PR requires an **approving review from the repository owner**
   before the "Merge" button is available at all — see `.github/
   CODEOWNERS` and this repo's own branch-protection settings
   (Settings → Branches → `main`: "Require a pull request before
   merging", "Require approvals" (≥1), "Require review from Code
   Owners", "Require status checks to pass before merging" with the CI
   job(s) selected, "Do not allow bypassing the above settings"). These
   are GitHub repository settings, not something a file in this repo can
   enforce on its own — CODEOWNERS only takes effect once the branch
   protection rule requiring it is turned on.
4. Once approved and merged, the **Release** workflow
   (`.github/workflows/release.yml`) runs automatically: it waits for
   CI to report success on the new `main` commit, then tags and
   publishes a new GitHub Release, auto-incrementing the `PATCH`
   version (`v0.1.0` → `v0.1.1` → …) from the latest existing tag. A
   `MINOR`/`MAJOR` bump is a manual `git tag` — the next automatic
   release continues incrementing `PATCH` from whatever tag is latest.

In short: **branch → PR → CI → owner approval → merge → automatic
release.** No step is skippable by design.

## Everything else

See `CLAUDE.md` (local, not checked into this repository) for coding
conventions, architecture references, and the commit-prefix discipline
(`scaffold:`/`feat:`/`fix:`/`docs:`/`refactor:`/`test:`) this project
follows.
