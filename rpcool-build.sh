#!/bin/bash

# Exit immediately if a command exits with a non-zero status, and treat unset variables as an error.
set -eu

# Function to print messages in red
echo_red() {
  echo -e "\033[0;31m$1\033[0m"
}

# Check if .git directory exists and move it to gitfiles if it does
move_git_to_gitfiles() {
  if [ -d .git ] && [ ! -d gitfiles ]; then
    echo_red "Moving .git to gitfiles..."
    mv .git gitfiles
  elif [ -d gitfiles ]; then
    echo_red ".git directory is already in gitfiles. Skipping move."
  elif [ ! -d .git ] && [ ! -d gitfiles ]; then
    echo_red "Neither .git nor gitfiles directory exists. Please check your repository."
    exit 1
  fi
}

# Move the gitfiles directory back to .git
move_gitfiles_to_git() {
  if [ -d gitfiles ] && [ ! -d .git ]; then
    echo_red "Moving gitfiles back to .git..."
    mv gitfiles .git
  elif [ -d .git ]; then
    echo_red ".git directory is already present. Skipping move back."
  elif [ ! -d gitfiles ] && [ ! -d .git ]; then
    echo_red "gitfiles directory not found and .git is missing. Please check your setup."
    exit 1
  fi
}

# Execute the moves and make command
move_git_to_gitfiles
echo_red "Running make with -j\$(nproc)..."
make -j$(nproc)
move_gitfiles_to_git

echo_red "Operation completed successfully."

