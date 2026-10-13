#!/usr/bin/env bash
# Installe l'outillage de développement du CLI dans ~/.local, sans sudo : Node, Gitleaks, OSV-Scanner, uv, Semgrep.
# Versions épinglées (au moins deux semaines d'ancienneté au moment du choix), sommes de contrôle vérifiées.
#
#   bash cli/scripts/dev-tools.sh          puis   export PATH="$HOME/.local/bin:$PATH"
#
# Idempotent : un outil déjà présent à la bonne version n'est pas retéléchargé.
set -euo pipefail

NODE_VERSION=22.23.3
# npm 10 (livré avec Node 22) plante sur l'arbre de dépendances de Vitest (« reading 'edgesOut' ») : npm 11 corrige.
NPM_VERSION=11.6.2
GITLEAKS_VERSION=8.30.1
OSV_VERSION=2.6.0
UV_VERSION=0.12.19
SEMGREP_VERSION=1.178.0

BIN="$HOME/.local/bin"
OPT="$HOME/.local/opt"
mkdir -p "$BIN" "$OPT"
export PATH="$BIN:$PATH"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

case "$(uname -m)" in
  x86_64) ARCH=x64; GOARCH=amd64; GITLEAKS_ARCH=x64; UV_ARCH=x86_64 ;;
  aarch64) ARCH=arm64; GOARCH=arm64; GITLEAKS_ARCH=arm64; UV_ARCH=aarch64 ;;
  *) echo "architecture non prise en charge : $(uname -m)" >&2; exit 1 ;;
esac

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

# Vérifie que la somme SHA-256 de $1 figure, associée au nom $2, dans le fichier de sommes $3.
verify() {
  local want
  want=$(grep -E "[[:space:]]\*?$2\$" "$3" | awk '{print $1}' | head -1)
  [ -n "$want" ] || { echo "somme absente pour $2" >&2; exit 1; }
  echo "$want  $1" | sha256sum -c --quiet - || { echo "SOMME INCORRECTE : $2" >&2; exit 1; }
}

# --- Node
if ! "$BIN/node" --version 2>/dev/null | grep -qx "v$NODE_VERSION"; then
  f="node-v$NODE_VERSION-linux-$ARCH.tar.xz"
  fetch "https://nodejs.org/dist/v$NODE_VERSION/$f" "$WORK/$f"
  fetch "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt" "$WORK/node.sums"
  verify "$WORK/$f" "$f" "$WORK/node.sums"
  rm -rf "$OPT/node" && mkdir -p "$OPT/node"
  tar -xJf "$WORK/$f" -C "$OPT/node" --strip-components=1
  for b in node npm npx; do ln -sf "$OPT/node/bin/$b" "$BIN/$b"; done
fi
if [ "$("$BIN/npm" --version)" != "$NPM_VERSION" ]; then
  "$BIN/npm" install -g --no-audit --no-fund "npm@$NPM_VERSION" >/dev/null
fi
echo "node     $("$BIN/node" --version), npm $("$BIN/npm" --version)"

# --- Gitleaks
if ! "$BIN/gitleaks" version 2>/dev/null | grep -q "$GITLEAKS_VERSION"; then
  f="gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"
  base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
  fetch "$base/$f" "$WORK/$f"
  fetch "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" "$WORK/gitleaks.sums"
  verify "$WORK/$f" "$f" "$WORK/gitleaks.sums"
  tar -xzf "$WORK/$f" -C "$WORK" gitleaks
  install -m 755 "$WORK/gitleaks" "$BIN/gitleaks"
fi
echo "gitleaks $("$BIN/gitleaks" version)"

# --- OSV-Scanner
if ! "$BIN/osv-scanner" --version 2>/dev/null | grep -q "$OSV_VERSION"; then
  f="osv-scanner_linux_$GOARCH"
  base="https://github.com/google/osv-scanner/releases/download/v$OSV_VERSION"
  fetch "$base/$f" "$WORK/$f"
  fetch "$base/osv-scanner_SHA256SUMS" "$WORK/osv.sums"
  verify "$WORK/$f" "$f" "$WORK/osv.sums"
  install -m 755 "$WORK/$f" "$BIN/osv-scanner"
fi
echo "osv      $("$BIN/osv-scanner" --version | head -1)"

# --- uv (gestionnaire Python autonome : Semgrep sans python3-venv ni sudo)
if ! "$BIN/uv" --version 2>/dev/null | grep -q "$UV_VERSION"; then
  f="uv-$UV_ARCH-unknown-linux-gnu.tar.gz"
  base="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
  fetch "$base/$f" "$WORK/$f"
  fetch "$base/$f.sha256" "$WORK/uv.sums"
  verify "$WORK/$f" "$f" "$WORK/uv.sums"
  tar -xzf "$WORK/$f" -C "$WORK"
  install -m 755 "$WORK/uv-$UV_ARCH-unknown-linux-gnu/uv" "$BIN/uv"
  install -m 755 "$WORK/uv-$UV_ARCH-unknown-linux-gnu/uvx" "$BIN/uvx"
fi
echo "uv       $("$BIN/uv" --version)"

# --- Semgrep (version épinglée, dans un environnement isolé géré par uv)
if ! "$BIN/semgrep" --version 2>/dev/null | grep -qx "$SEMGREP_VERSION"; then
  "$BIN/uv" tool install --quiet --force --python 3.12 "semgrep==$SEMGREP_VERSION"
fi
echo "semgrep  $("$BIN/semgrep" --version)"
