#!/usr/bin/env bash
# Construit le paquet publié sur les releases GitHub (dotation-X.Y.Z.tgz, dotation.tgz, SHA256SUMS) dans release/.
# Les dépendances de production sont embarquées dans le paquet (bundleDependencies), installées depuis package-lock.json :
# « npm install -g <url> » installe exactement les versions testées, y compris les dépendances indirectes, sans
# rien résoudre sur le registre npm (un npm-shrinkwrap.json est ignoré pour une installation depuis une URL).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(node -p 'require("./package.json").version')
OUT=release
# Même npm que celui qui lance le script (npm 11 en CI : npm 10 plante sur l'arbre de dépendances de Vitest).
NPM=(npm)
[ -n "${npm_execpath:-}" ] && NPM=(node "$npm_execpath")
rm -rf "$OUT" && mkdir -p "$OUT"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

"${NPM[@]}" run -s build
cp -r package.json README.md README.fr.md LICENSE dist rules engines skills "$STAGE/"
cp package-lock.json "$STAGE/package-lock.json"
# Rien à exécuter à l'installation, et pas de publication accidentelle sur le registre npm (« private »).
node -e '
  const fs = require("fs"); const p = process.argv[1] + "/package.json";
  const pkg = JSON.parse(fs.readFileSync(p, "utf8"));
  pkg.scripts = {}; pkg.bundleDependencies = Object.keys(pkg.dependencies);
  fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + "\n");
' "$STAGE"
(cd "$STAGE" && "${NPM[@]}" ci --omit=dev --ignore-scripts --no-audit --no-fund --silent && rm package-lock.json && "${NPM[@]}" pack --silent --pack-destination "$OLDPWD/$OUT" >/dev/null)
cp "$OUT/dotation-$VERSION.tgz" "$OUT/dotation.tgz"
(cd "$OUT" && sha256sum "dotation-$VERSION.tgz" dotation.tgz > SHA256SUMS)
tar -tzf "$OUT/dotation-$VERSION.tgz" | sort > "$OUT/CONTENTS.txt"
echo "release/dotation-$VERSION.tgz ($(du -h "$OUT/dotation-$VERSION.tgz" | cut -f1), $(wc -l < "$OUT/CONTENTS.txt") fichiers)"
