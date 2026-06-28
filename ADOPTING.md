# Adopting the standard

Work top to bottom. `grep -rn 'TODO\|<PLACEHOLDER>\|<SHA>\|net.example\|example/repo' .`
finds everything that needs a project-specific value.

## 1. Copy the tree

Copy everything except this file, `README.md`, and `STANDARD.md` (those describe
the standard; they aren't part of a project) into the new repo. Keep `.github/`,
`scripts/`, `VERSION`, and `CONTRIBUTING.md`.

## 2. Branch model

- Create the long-lived `dev` branch; make `main` release-only.
- Default branch → `dev` (so PRs open against it by default).

## 3. Branch protection / required checks

Decide the required check names *before* writing jobs to match. The standard ships:
- one required check per language area (e.g. `lint`, `test`), and
- one **aggregator** check name per fan-out group (e.g. `rust`).

Set these as required in branch-protection for `dev` and `main`. The aggregator
name is what you protect — never the individual fanned-out jobs.

## 4. Fill in CI (`.github/workflows/ci.yml`)

- [ ] Rewrite the `case` arms in the `changes` job for your directories/extensions.
- [ ] Add one output per area and one gated job per area.
- [ ] For any area split into parallel jobs, add an `if: always()` aggregator
      (template included, commented).
- [ ] Pin every `uses:` to a commit SHA with a `# vX.Y.Z` comment.

## 5. Fill in the release pipeline

- [ ] `build-release.yml`: replace the build/package steps with your artifact's
      build. Keep the draft-then-publish release shape.
- [ ] `autotag.yml` / `release.yml`: set the branches and the artifact glob.
- [ ] Set `VERSION` to your starting floor (e.g. `0.1.0`).
- [ ] Confirm `paths-ignore` carve-outs match your repo (don't ignore the files
      that change the shipped artifact).

## 6. Dependabot (`.github/dependabot.yml`)

- [ ] Keep the `github-actions` ecosystem (works for any repo with workflows).
- [ ] Add an ecosystem block per package manager you actually use; drop the rest.
- [ ] Point `target-branch` at `dev`.

## 7. Templates

- [ ] `ISSUE_TEMPLATE/config.yml`: set the security-advisory URL, Discussions URL,
      and roadmap link. **The security link is not optional.**
- [ ] Replace the **invariant checkboxes** in `feature_request.yml` / `task.yml`
      with your project's real guarantees (or remove if none).
- [ ] Tune the component/area dropdowns to your subsystems.
- [ ] `PULL_REQUEST_TEMPLATE.md`: point the "docs moved" row at your real docs.

## 8. Hooks

- [ ] Edit `scripts/install-hooks.sh` so the pre-push hook runs *your* fast linter.
- [ ] Document `./scripts/install-hooks.sh` in your README/CONTRIBUTING.

## 9. Verify before relying on it

- [ ] Open a throwaway docs-only PR → confirm language jobs **skip** and the PR is
      still mergeable (proves "skip, don't ignore" works with your protection).
- [ ] Open a PR that touches one area → confirm only that area's jobs run.
- [ ] Merge a trivial change to `dev` → confirm a prerelease tag + draft release
      appear, then publish.
- [ ] Bump `VERSION` minor in a PR → confirm the next release takes the floor once.
