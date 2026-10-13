#!/usr/bin/env bash
# Copie le CLI (cli/ du monorepo privé, état du commit HEAD) dans une copie locale du dépôt public
# github.com/Sami-BUTRT/dotation-cli, puis crée un commit. Ne pousse rien : relire le diff, puis « git push ».
# Exclus : scripts qui dépendent du dépôt privé (API). Auteur : adresse noreply de GitHub (pas d'adresse personnelle).
# Usage : cli/scripts/publish-public-repo.sh <copie-locale-de-dotation-cli>
set -euo pipefail
DEST=${1:?usage : $0 <copie-locale-de-dotation-cli>}
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
[ -d "$DEST/.git" ] || { echo "$DEST n'est pas un dépôt git" >&2; exit 1; }
[ -z "$(git -C "$ROOT" status --porcelain -- cli)" ] || { echo "cli/ a des modifications non committées : committe d'abord" >&2; exit 1; }
SHA=$(git -C "$ROOT" rev-parse --short HEAD)
EXCLUDE=(cli/scripts/cloud-e2e.sh)

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
git -C "$ROOT" archive HEAD cli | tar -x -C "$TMP"
for f in "${EXCLUDE[@]}"; do rm -f "$TMP/$f"; done
# Le contenu du dépôt public est exactement celui de cli/ (hors exclusions) : le reste est supprimé.
find "$DEST" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -a "$TMP/cli/." "$DEST/"

cd "$DEST"
git add -A
if git diff --cached --quiet; then echo "rien à publier"; exit 0; fi
git -c user.name="Sami Hameg" -c user.email="253724606+Sami-BUTRT@users.noreply.github.com" \
  commit -q -m "Sync from the dotation monorepo ($SHA)"
git log --oneline -1
git show --stat --format= HEAD | tail -1
echo "Relis le diff (git -C $DEST show), puis : git -C $DEST push"
