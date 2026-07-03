#!/usr/bin/env python3
"""Regression tests for scripts/gen-changelog.sh.

gen-changelog.sh runs inside the Debian build (via debian/rules) and derives
the package version + changelog from git tags. It iterates every `v*` tag, so
tags that are NOT part of release history must not break it.

pr-test-build.yml tags a labeled PR's HEAD as `v<ver>-pr<N>.<...>`. That commit
is unmerged and can share no common ancestor with the release HEAD (e.g. after
dev is rebased), which previously aborted the build: a `git merge-base <tag>
HEAD` under `set -e` exited non-zero on such a tag. These tests pin that a
PR-preview tag on an unrelated commit (a) doesn't break generation and (b) is
excluded from the changelog, while a real release tag still versions the top
stanza.

Run: python3 -m pytest tests/test_gen_changelog.py -v
"""

import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "gen-changelog.sh")

# Deterministic identity so `git commit`/`git tag` work without a global config.
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00 +0000",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00 +0000",
    "DEBFULLNAME": "Test Builder",
    "DEBEMAIL": "test@example.com",
}


def git(repo, *args):
    """Run a git command in `repo`, returning stripped stdout."""
    return subprocess.run(
        ["git", "-C", repo, *args],
        env=GIT_ENV,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo, message, marker):
    """Create an empty-ish commit touching a unique file, return its short sha."""
    with open(os.path.join(repo, marker), "w") as fh:
        fh.write(marker)
    git(repo, "add", marker)
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "--short", "HEAD")


class GenChangelogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = self._tmp.name
        git(self.repo, "init", "-q", "-b", "main")

        # Mainline release history: v0.1.0 -> v0.2.0 -> HEAD.
        commit(self.repo, "Initial release", "a")
        git(self.repo, "tag", "v0.1.0")
        commit(self.repo, "feat: something user-visible", "b")
        git(self.repo, "tag", "v0.2.0")
        self.head_sha = commit(self.repo, "feat: another feature", "c")
        # A mainline prerelease tag (kept in the changelog).
        git(self.repo, "tag", f"v0.2.1-dev.20260101.{self.head_sha}")

        # An UNMERGED PR-preview tag on an orphan commit — no common ancestor
        # with main, so `git merge-base` against HEAD would fail. This is the
        # exact shape that broke the release build.
        git(self.repo, "checkout", "-q", "--orphan", "pr-branch")
        pr_sha = commit(self.repo, "fix: work in progress on a PR", "d")
        git(self.repo, "tag", f"v0.2.1-pr99.{pr_sha}")
        self.assertEqual(
            subprocess.run(
                ["git", "-C", self.repo, "merge-base", f"v0.2.1-pr99.{pr_sha}", "main"],
                env=GIT_ENV,
                capture_output=True,
            ).returncode,
            1,
            "test setup should produce a pr tag with no common ancestor",
        )
        git(self.repo, "checkout", "-q", "main")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self):
        return subprocess.run(
            ["bash", SCRIPT],
            cwd=self.repo,
            env=GIT_ENV,
            capture_output=True,
            text=True,
        )

    def _changelog(self):
        with open(os.path.join(self.repo, "debian", "changelog")) as fh:
            return fh.read()

    def test_pr_preview_tag_on_unmerged_commit_does_not_break_changelog(self):
        # Build "at" the release: tag HEAD as the plain release, as autotag does.
        git(self.repo, "tag", "v0.2.1")
        result = self._run()
        self.assertEqual(
            result.returncode, 0, f"gen-changelog.sh failed:\n{result.stderr}"
        )
        # Top stanza is the plain release version, not a prerelease/pr form.
        self.assertRegex(
            self._changelog().splitlines()[0],
            r"^luks-enroll \(0\.2\.1-1\) ",
        )

    def test_pr_preview_tags_are_excluded_from_changelog(self):
        git(self.repo, "tag", "v0.2.1")
        self.assertEqual(self._run().returncode, 0)
        changelog = self._changelog()
        self.assertNotIn("pr99", changelog)
        self.assertNotIn("~pr", changelog)
        # Real releases and mainline prereleases are still present.
        self.assertIn("(0.2.0-1)", changelog)
        self.assertIn("(0.1.0-1)", changelog)

    def test_dev_prerelease_head_versions_top_stanza(self):
        # Building at a -dev prerelease tag (the push-to-dev path) versions the
        # top stanza with the '~' prerelease separator and still succeeds.
        result = self._run()
        self.assertEqual(
            result.returncode, 0, f"gen-changelog.sh failed:\n{result.stderr}"
        )
        self.assertRegex(
            self._changelog().splitlines()[0],
            r"^luks-enroll \(0\.2\.1~dev\.20260101\.[0-9a-f]+-1\) ",
        )


if __name__ == "__main__":
    unittest.main()
