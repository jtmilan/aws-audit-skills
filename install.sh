#!/usr/bin/env bash
# Symlink every skill in skills/ into ~/.claude/skills/.
#
# Adding a new skill: create skills/<name>/SKILL.md, re-run this script.
# No edits to this file required — the loop discovers everything under skills/.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${HOME}/.claude/skills"

mkdir -p "${TARGET_DIR}"

shopt -s nullglob
for skill_dir in "${REPO_DIR}/skills/"*/; do
  name="$(basename "${skill_dir}")"
  link="${TARGET_DIR}/${name}"

  if [[ -L "${link}" ]]; then
    if [[ "$(readlink "${link}")" == "${skill_dir%/}" ]]; then
      echo "ok    ${name} (already linked)"
      continue
    fi
    echo "warn  ${name} link points elsewhere: $(readlink "${link}")"
    continue
  fi
  if [[ -e "${link}" ]]; then
    echo "skip  ${name} (target exists, not a symlink)"
    continue
  fi

  ln -s "${skill_dir%/}" "${link}"
  echo "link  ${name} -> ${skill_dir%/}"
done

echo
echo "Installed skills are now available in ~/.claude/skills/"
