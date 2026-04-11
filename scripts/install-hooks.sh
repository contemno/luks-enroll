#!/bin/bash
# Install git hooks for this project.
# Usage: ./scripts/install-hooks.sh

set -euo pipefail

HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

cat > "${HOOKS_DIR}/pre-push" << 'HOOK'
#!/bin/bash
# Pre-push hook: lint + syntax check.
# Runs fast (~2s). Full tests run in CI on PRs.

set -euo pipefail

echo "pre-push: running ruff..."
if command -v ruff &>/dev/null; then
    ruff check . && ruff format --check .
else
    echo "  ruff not installed, skipping (pip install ruff)"
fi

echo "pre-push: syntax check..."
python3 -c "import ast; ast.parse(open('dist/usr/bin/luks-enroll').read())"
python3 -c "import ast; ast.parse(open('dist/usr/sbin/luks-enroll-service').read())"

echo "pre-push: OK"
HOOK

chmod +x "${HOOKS_DIR}/pre-push"
echo "Installed pre-push hook to ${HOOKS_DIR}/pre-push"
