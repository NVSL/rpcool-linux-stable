#!/bin/bash
set -eu

# Define the main branch you're comparing against, usually master or main
MAIN_BRANCH="v6.1.37"

# Log the main branch name
echo "Main branch: $MAIN_BRANCH"

# Find the common ancestor of the current branch and the main branch
COMMON_ANCESTOR=$(git merge-base HEAD $MAIN_BRANCH)

# Log the common ancestor commit ID
echo "Common ancestor commit ID: $COMMON_ANCESTOR"

# Display information about the common ancestor
echo "Common ancestor details:"
git show --no-patch --no-notes $COMMON_ANCESTOR

# Generate patch files for all commits since the common ancestor
# and consolidate them into a single patch file named "rpcool.patch"
git format-patch $COMMON_ANCESTOR..HEAD --stdout > rpcool.patch

echo "Patch file created: rpcool.patch"

