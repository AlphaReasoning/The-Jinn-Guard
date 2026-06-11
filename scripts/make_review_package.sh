#!/usr/bin/env bash
#
# make_review_package.sh — build the clean reviewer package to send a professor.
#
# Produces jinn-guard-v1.0-review.tar.gz and .zip from the committed source via
# `git archive`, so the package contains ONLY tracked files — no target/, no
# compiled .o/.bc objects, no vmlinux.h, no .git history. The recipient extracts
# it and runs scripts/run_professor_validation.sh (see PROFESSOR_VALIDATION.md).
#
# Usage (from the repo root):
#   bash scripts/make_review_package.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NAME="jinn-guard-v1.0-review"
REF="${1:-HEAD}"

command -v git >/dev/null 2>&1 || { echo "git is required"; exit 1; }

# Refuse to package a tree with uncommitted changes (the archive uses committed
# state); commit or stash first so the package matches the repository exactly.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "WARNING: you have uncommitted changes. The package is built from the last"
  echo "commit ($REF) and will NOT include them. Commit first for an exact match."
fi

git archive --format=tar.gz --prefix=jinn-guard/ "$REF" -o "$NAME.tar.gz"
git archive --format=zip    --prefix=jinn-guard/ "$REF" -o "$NAME.zip"

# Sanity: the package must not contain build artifacts.
if tar tzf "$NAME.tar.gz" | grep -qE "/target/|\.o$|\.bc$|vmlinux\.h$"; then
  echo "ERROR: package unexpectedly contains build artifacts. Aborting."
  rm -f "$NAME.tar.gz" "$NAME.zip"
  exit 1
fi

echo "Clean review package built:"
ls -lh "$NAME.tar.gz" "$NAME.zip"
echo
echo "Send either file to the reviewer. They extract it and run:"
echo "  cd jinn-guard && bash scripts/run_professor_validation.sh"
