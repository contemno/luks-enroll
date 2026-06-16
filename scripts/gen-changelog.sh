#!/bin/bash
# gen-changelog.sh — generate debian/changelog from git history.
#
# Strategy:
#   * One stanza per annotated/lightweight tag matching v*
#   * Bullets are the first line of each commit message in the range
#   * Merge commits and commits whose subject starts with "chore:" are skipped
#   * If the working tree has commits past the latest tag, an UNRELEASED
#     stanza is generated using the version from the latest tag with a
#     ~git<shortsha> suffix so it sorts below the next real release
#
# Output: debian/changelog (overwritten)
#
# Invoked from debian/rules during the build.

set -euo pipefail

PKG="luks-enroll"
MAINTAINER_NAME="${DEBFULLNAME:-Josh}"
MAINTAINER_EMAIL="${DEBEMAIL:-josh@contemno.net}"
DISTRIBUTION="unstable"

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(readlink -f "$0")")")"

# Fall back to a placeholder changelog when not in a git checkout
# (e.g. building from an unpacked source tarball).
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    if [ -s debian/changelog ]; then
        echo "gen-changelog: not a git checkout, keeping existing debian/changelog" >&2
        exit 0
    fi
    echo "gen-changelog: not a git checkout and no debian/changelog present" >&2
    exit 1
fi

format_date() {
    # RFC 5322 date for the commit hash given as $1.
    git log -1 --format=%aD "$1"
}

# Convert a tag to a Debian upstream version:
#   "v1.2.3"                      -> "1.2.3"
#   "v1.2.3-dev.20260616.2eaa4ff" -> "1.2.3~dev.20260616.2eaa4ff"
# Any prerelease suffix after the X.Y.Z core has its leading '-' turned into
# '~' so the prerelease sorts *below* the corresponding release in dpkg's
# version ordering, and the upstream version carries no '-' (which would
# otherwise be read as the debian-revision separator).
tag_to_upstream() {
    local tag="${1#v}"
    if echo "$tag" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        printf '%s' "$tag"
    else
        printf '%s' "$tag" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+)-/\1~/'
    fi
}

emit_stanza() {
    local version="$1" range="$2" ref="$3"
    local body
    body="$(git log --no-merges --pretty=format:'%s' "$range" \
            | grep -vE '^(chore|ci|wip)(\(.*\))?:' || true)"
    if [ -z "$body" ]; then
        body="No user-visible changes."
    fi

    printf '%s (%s-1) %s; urgency=medium\n\n' "$PKG" "$version" "$DISTRIBUTION"
    printf '%s\n' "$body" | sed -E 's/^/  * /'
    printf '\n -- %s <%s>  %s\n\n' \
        "$MAINTAINER_NAME" "$MAINTAINER_EMAIL" "$(format_date "$ref")"
}

tags="$(git tag --list 'v*' --sort=-v:refname)"
out=""

# A tag pointing exactly at HEAD means we're building that tagged release (the
# auto-tag/release workflow tags the very commit it builds). Prefer a plain
# vX.Y.Z release tag over a prerelease tag sitting on the same commit.
head_tag="$(git tag --points-at HEAD --list 'v*' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)"
if [ -z "$head_tag" ]; then
    head_tag="$(git tag --points-at HEAD --list 'v*' | sort -V | tail -n1 || true)"
fi

if [ -n "$head_tag" ]; then
    # Building exactly at a tag: that tag's version is the package version, with
    # no UNRELEASED ~git suffix. Force its stanza to the top of the loop below so
    # dpkg reads it as the package version — the -v:refname sort otherwise ranks
    # a prerelease (e.g. -dev.*) above its corresponding release, which would
    # mis-version a real release as <release>~dev...~git... (sorting below it).
    tags="$head_tag"$'\n'"$(printf '%s\n' "$tags" | grep -vxF "$head_tag")"
elif [ -n "$tags" ]; then
    # Building past the latest tag (e.g. a local working-tree build): emit an
    # UNRELEASED stanza versioned <latest>~git<sha> so it sorts below the next
    # real release.
    latest_tag="$(printf '%s\n' "$tags" | head -n1)"
    if [ -n "$(git log --oneline "${latest_tag}..HEAD" 2>/dev/null)" ]; then
        upstream="$(tag_to_upstream "$latest_tag")"
        sha="$(git rev-parse --short HEAD)"
        out+="$(emit_stanza "${upstream}~git${sha}" "${latest_tag}..HEAD" HEAD)"$'\n'
    fi
else
    # No tags at all — single stanza covering the entire history.
    sha="$(git rev-parse --short HEAD)"
    upstream="0.0.0~git${sha}"
    out+="$(emit_stanza "$upstream" "HEAD" HEAD)"$'\n'
fi

# One stanza per tag, newest to oldest.
prev=""
for tag in $tags; do
    upstream="$(tag_to_upstream "$tag")"
    if [ -z "$prev" ]; then
        range="$tag"
    else
        range="${tag}..${prev}"
        # We want commits *belonging to* $tag, i.e. up to and including $tag,
        # but excluding commits from older tags. Recompute:
        range="$(git merge-base "$tag" HEAD)..$tag"
        # Simpler: list commits reachable from $tag but not from the previous
        # (older) tag.
    fi
    # Always express the range as "older_tag..tag"; for the oldest tag use the
    # full history up to that tag.
    older="$(printf '%s\n' "$tags" | awk -v t="$tag" 'found{print;exit} $0==t{found=1}')"
    if [ -n "$older" ]; then
        range="${older}..${tag}"
    else
        range="$tag"
    fi
    out+="$(emit_stanza "$upstream" "$range" "$tag")"$'\n'
    prev="$tag"
done

mkdir -p debian
printf '%s' "$out" > debian/changelog
