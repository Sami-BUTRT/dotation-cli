import { readFileSync } from "node:fs";
import { packagePath } from "../paths.js";

// Détection des noms de dépendances « presque » identiques à un paquet très populaire (typosquatting, noms
// inventés par une IA). Les noms populaires sont embarqués (cli/data/popular-packages.json) : aucun accès réseau.

export type Ecosystem = "npm" | "pypi";

export interface Dep {
  name: string;
  /** 1-based, 0 si inconnue. */
  line: number;
}

interface Index {
  set: Set<string>;
  byLength: Map<number, string[]>;
  /** Nom sans séparateurs (- _ .) -> noms populaires. */
  bySquashed: Map<string, string[]>;
}

const SEP = /[-_.]/g;
const squash = (n: string) => n.replace(SEP, "");

let cache: Record<Ecosystem, Index> | null = null;

function buildIndex(names: string[]): Index {
  const idx: Index = { set: new Set(names), byLength: new Map(), bySquashed: new Map() };
  for (const n of names) {
    const l = idx.byLength.get(n.length) ?? [];
    l.push(n);
    idx.byLength.set(n.length, l);
    const s = squash(n);
    const q = idx.bySquashed.get(s) ?? [];
    q.push(n);
    idx.bySquashed.set(s, q);
  }
  return idx;
}

export function popularIndex(): Record<Ecosystem, Index> {
  if (!cache) {
    const raw = JSON.parse(readFileSync(packagePath("data/popular-packages.json"), "utf8")) as Record<
      Ecosystem,
      string[]
    >;
    cache = { npm: buildIndex(raw.npm), pypi: buildIndex(raw.pypi) };
  }
  return cache;
}

/** Tests uniquement : remplace les listes populaires (clés absentes = données embarquées). `null` rétablit tout. */
export function setPopularForTests(override: Partial<Record<Ecosystem, string[]>> | null): void {
  cache = null;
  if (!override) return;
  const real = popularIndex();
  cache = {
    npm: override.npm ? buildIndex(override.npm) : real.npm,
    pypi: override.pypi ? buildIndex(override.pypi) : real.pypi,
  };
}

/** Normalisation : npm en minuscules, PyPI selon la PEP 503. */
export function normalizeName(eco: Ecosystem, name: string): string {
  return eco === "npm" ? name.toLowerCase() : name.toLowerCase().replace(/[-_.]+/g, "-");
}

/** Distance de Damerau-Levenshtein (transpositions voisines), abandonne au-delà de `max` (renvoie max + 1). */
export function damerau(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev2: number[] = [];
  let prev: number[] = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur: number[] = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min((prev[j] ?? 0) + 1, (cur[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, (prev2[j - 2] ?? 0) + 1);
      }
      cur.push(v);
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length] ?? max + 1;
}

const PREFIXES = ["python-", "node-", "py-", "js-", "py"];
const SUFFIXES = ["-python", "-node", "-js", ".js", "-py", "-ts"];
const MIN_LEN = 5;
const MAX_SHOWN = 3;

/** Variantes d'un nom en retirant ou ajoutant un préfixe / suffixe d'écosystème. */
function affixVariants(name: string): string[] {
  const out: string[] = [];
  for (const p of PREFIXES) {
    if (name.startsWith(p) && name.length - p.length >= 4) out.push(name.slice(p.length));
    out.push(p + name);
  }
  for (const s of SUFFIXES) {
    if (name.endsWith(s) && name.length - s.length >= 4) out.push(name.slice(0, -s.length));
    out.push(name + s);
  }
  return out;
}

const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const MAX_DEPS = 2000;
/** Taille maximale d'un manifeste, en octets (à vérifier par stat avant lecture, voir `withinManifestLimit`). */
export const MAX_FILE = 1_000_000;
export const withinManifestLimit = (bytes: number) => bytes <= MAX_FILE;
const tooBig = (t: string) => t.length > MAX_FILE || Buffer.byteLength(t, "utf8") > MAX_FILE;
const MAX_NAME = 214;
const validNpm = (n: string) => n.length <= MAX_NAME && NPM_NAME.test(n);
const validPypi = (n: string) => n.length <= MAX_NAME && PYPI_NAME.test(n);

/** Préfixe commun (jusqu'au dernier « - », « / » ou « . » inclus) ; 0 si inférieur à 6 caractères. */
function familyPrefix(a: string, b: string): number {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  const cut = Math.max(a.lastIndexOf("-", i - 1), a.lastIndexOf("/", i - 1), a.lastIndexOf(".", i - 1)) + 1;
  return cut >= 6 ? cut : 0;
}

/** Paquet scopé : seul un scope presque identique à un scope populaire (@type/node) ou un nom collé est suspect. */
function scopedLookalikes(idx: Index, name: string): string[] {
  const slash = name.indexOf("/");
  const scope = name.slice(0, slash);
  const rest = name.slice(slash + 1);
  const found = new Set<string>();
  const collapsed = name.replace("@", "").replace("/", "");
  if (collapsed.length >= MIN_LEN && idx.set.has(collapsed)) found.add(collapsed);
  if (scope.length >= 5) {
    for (const p of idx.set) {
      if (p[0] !== "@") continue;
      const ps = p.slice(0, p.indexOf("/"));
      if (ps !== scope && p.slice(p.indexOf("/") + 1) === rest && damerau(scope, ps, 1) <= 1) found.add(p);
    }
  }
  return [...found].sort().slice(0, MAX_SHOWN);
}

/** Noms populaires dont `name` est un presque-sosie ; vide si `name` est lui-même populaire ou sans ressemblance. */
export function lookalikes(eco: Ecosystem, rawName: string): string[] {
  const idx = popularIndex()[eco];
  const name = normalizeName(eco, rawName);
  if (idx.set.has(name) || name.length < MIN_LEN) return [];
  if (eco === "npm" && name.startsWith("@")) return name.includes("/") ? scopedLookalikes(idx, name) : [];
  const found = new Set<string>();

  for (const p of idx.bySquashed.get(squash(name)) ?? []) if (p !== name) found.add(p);
  for (const v of affixVariants(name)) if (idx.set.has(v)) found.add(v);

  const max = name.length >= 10 ? 2 : 1;
  const base = name.replace(/\d+$/, "");
  for (let len = name.length - max; len <= name.length + max; len++) {
    for (const p of idx.byLength.get(len) ?? []) {
      if (p[0] === "@") continue;
      if (max === 2 && p[0] !== name[0]) continue;
      // « vue » / « vue3 » : un numéro de version en fin de nom n'est pas une faute de frappe.
      if (p.replace(/\d+$/, "") === base) continue;
      const k = familyPrefix(name, p);
      if (k) {
        const a = name.slice(k);
        const b = p.slice(k);
        if (a.length >= 5 && b.length >= 5 && damerau(a, b, a.length >= 10 ? 2 : 1) <= (a.length >= 10 ? 2 : 1))
          found.add(p);
        continue;
      }
      if (damerau(name, p, max) <= max) found.add(p);
    }
  }
  return [...found].sort((a, b) => damerau(name, a, 9) - damerau(name, b, 9) || a.localeCompare(b)).slice(0, MAX_SHOWN);
}

// --- Lecture des manifestes ---

const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

/** Dépendances npm du registre public (ignore workspace:, file:, link:, git, alias npm:). */
export function parsePackageJson(text: string): Dep[] {
  if (tooBig(text)) return [];
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof json !== "object" || json === null) return [];
  const own = (json as Record<string, unknown>).name;
  const lines = text.split(/\r?\n/);
  const out: Dep[] = [];
  for (const section of NPM_SECTIONS) {
    const deps = (json as Record<string, unknown>)[section];
    if (typeof deps !== "object" || deps === null) continue;
    const sectionAt = lines.findIndex((l) => l.includes(`"${section}"`));
    let cursor = sectionAt < 0 ? 0 : sectionAt;
    for (const [name, spec] of Object.entries(deps)) {
      if (out.length >= MAX_DEPS) return out;
      if (
        name === own ||
        !validNpm(name) ||
        typeof spec !== "string" ||
        /^(?:workspace:|file:|link:|npm:|git|https?:|github:|[./~])/.test(spec)
      )
        continue;
      let i = -1;
      // Recherche bornée à la section (fin sur une ligne « } ») : pas de balayage jusqu'à la fin du fichier.
      for (let n = cursor; n < lines.length; n++) {
        if (lines[n]?.includes(`"${name}"`)) {
          i = n;
          break;
        }
        if (n > cursor && /^\s*\}/.test(lines[n] ?? "")) break;
      }
      if (i >= 0) cursor = i + 1;
      // Nom introuvable (échappements \u, minifié) : ligne de la section, curseur inchangé.
      out.push({ name, line: i >= 0 ? i + 1 : sectionAt + 1 || 1 });
    }
  }
  return out;
}

export function parseRequirements(text: string): Dep[] {
  const out: Dep[] = [];
  if (tooBig(text)) return out;
  text.split(/\r?\n/).forEach((raw, i) => {
    if (out.length >= MAX_DEPS) return;
    const l = raw.trim();
    if (!l || l.startsWith("#") || l.startsWith("-") || l.includes("://") || l.startsWith("git+") || l.startsWith("."))
      return;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(l);
    if (m?.[1] && validPypi(m[1])) out.push({ name: m[1], line: i + 1 });
  });
  return out;
}

const PEP508_NAME = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;

/** [project].dependencies, optional-dependencies, dependency-groups et Poetry (lecture ligne à ligne, sans parseur TOML complet). */
export function parsePyproject(text: string): Dep[] {
  const out: Dep[] = [];
  let section = "";
  let inArray = false;
  if (tooBig(text)) return out;
  text.split(/\r?\n/).forEach((raw, i) => {
    if (out.length >= MAX_DEPS) return;
    const line = raw.replace(/\s#.*$/, "");
    const head = /^\s*\[\[?([^\]]+)\]\]?\s*$/.exec(line);
    if (head?.[1] && !inArray) {
      section = head[1].trim();
      return;
    }
    const poetry = /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[\w-]+\.dependencies)$/.test(section);
    if (poetry) {
      const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
      if (m?.[1] && m[1].toLowerCase() !== "python" && validPypi(m[1])) out.push({ name: m[1], line: i + 1 });
      return;
    }
    const arrays =
      section === "project" || section === "project.optional-dependencies" || section === "dependency-groups";
    if (!arrays) return;
    let rest = line;
    if (!inArray) {
      const start = /^\s*([\w-]+)\s*=\s*\[(.*)$/.exec(line);
      if (!start || (section === "project" && start[1] !== "dependencies")) return;
      inArray = true;
      rest = start[2] ?? "";
    }
    // Chaînes entre guillemets (extras « pkg[extra] » compris) ; seul un « ] » hors guillemets ferme le tableau.
    let depth = 0;
    for (const t of rest.matchAll(/"([^"]*)"|'([^']*)'|([[\]])/g)) {
      if (t[3] === "[") depth++;
      else if (t[3] === "]") {
        if (depth === 0) {
          inArray = false;
          break;
        }
        depth--;
      } else {
        const str = t[1] ?? t[2] ?? "";
        const m = PEP508_NAME.exec(str);
        if (m?.[1] && validPypi(m[1]) && !str.includes("://") && !/^\s*@/.test(str))
          out.push({ name: m[1], line: i + 1 });
      }
    }
  });
  return out;
}
