#!/usr/bin/env node
// Régénère cli/data/popular-packages.json (BUILD uniquement ; le scan ne fait jamais de requête réseau).
// Usage : node scripts/update-popular-packages.mjs [nombre-par-écosystème, défaut 5000] [--with-pypi]
// PyPI est DÉSACTIVÉ par défaut (option --with-pypi) tant que la licence des données hugovk/top-pypi-packages
// n'est pas confirmée : sans l'option, le fichier contient "pypi": [] et seule la source npm.
import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const WITH_PYPI = args.includes("--with-pypi");
const N = Number(args.find((a) => !a.startsWith("--")) ?? 5000);
const PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json";
const NPM_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js";
const now = new Date().toISOString();

const get = async (url) => {
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
};
const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const uniq = (names) => [...new Set(names)];
// PEP 503 : minuscules, suites de - _ . réduites à un seul « - ».
const pep503 = (n) => n.toLowerCase().replace(/[-_.]+/g, "-");

const pypiRows = WITH_PYPI ? JSON.parse(await get(PYPI_URL)).rows : [];
const pypi = uniq(pypiRows.map((r) => String(r.project)).filter((n) => n.length <= 214 && PYPI_NAME.test(n)).map(pep503)).slice(0, N);
const npm = uniq([...(await get(NPM_URL)).matchAll(/^\s*'([^']+)',?\s*$/gm)].map((m) => m[1].toLowerCase()).filter((n) => n.length <= 214 && NPM_NAME.test(n))).slice(0, N);
if ((WITH_PYPI && pypi.length < 1000) || npm.length < 1000) throw new Error("données incomplètes, fichier non écrit");

const out = {
  generatedAt: now,
  sources: [
    ...(WITH_PYPI
      ? [
          {
            name: "hugovk/top-pypi-packages (noms seulement, sans compteurs)",
            url: PYPI_URL,
            license: "[À COMPLÉTER: licence des données hugovk/top-pypi-packages à valider par le porteur]",
            retrievedAt: now,
          },
        ]
      : []),
    {
      name: "wooorm/npm-high-impact",
      url: NPM_URL,
      license: "MIT",
      retrievedAt: now,
    },
  ],
  npm,
  pypi,
};
const file = join(dirname(fileURLToPath(import.meta.url)), "..", "data", "popular-packages.json");
await writeFile(file, `${JSON.stringify(out)}\n`);
console.log(`npm ${npm.length}, pypi ${pypi.length} -> ${file}`);
