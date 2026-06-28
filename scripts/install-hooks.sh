#!/bin/bash
# Install git hooks for this project.
# Usage: ./scripts/install-hooks.sh
#
# The pre-push hook is intentionally FAST (lint/format/syntax only, ~seconds) so
# nobody is tempted to disable it. Full tests run in CI on PRs.
#
# TODO: replace the lint body below with your project's fast checks.

set -euo pipefail

HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

cat > "${HOOKS_DIR}/pre-push" << 'HOOK'
#!/bin/bash
# Pre-push hook: fast lint + syntax check. Full tests run in CI.
set -euo pipefail

# --- TODO: project-specific fast checks ---------------------------------------
# Example (Python): ruff check . && ruff format --check .
# Example (Rust):   cargo fmt --all --check
# Keep it under a few seconds; skip gracefully if the tool isn't installed.
echo "pre-push: (no checks configured — edit scripts/install-hooks.sh)"
# ------------------------------------------------------------------------------

echo "pre-push: OK"
HOOK

chmod +x "${HOOKS_DIR}/pre-push"
echo "Installed pre-push hook to ${HOOKS_DIR}/pre-push"
