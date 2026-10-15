import { join } from "node:path";
import { run } from "../core/exec.js";
import { type FileSet, isEnvFile, readText, type ScanFile, type Scope } from "../core/files.js";
import type { Finding } from "../core/finding.js";
import { matchAny } from "../core/glob.js";
import { redactLine, truncate } from "../core/mask.js";
import {
  type Dep,
  type Ecosystem,
  lookalikes,
  parsePackageJson,
  parsePyproject,
  parseRequirements,
} from "./lookalike.js";
import type { RegexRule, Rule } from "./schema.js";

/** Lignes plus longues ignorées : fichiers minifiés, et protection contre les expressions trop coûteuses. */
const MAX_LINE = 2000;

export interface DetectInput {
  fileSet: FileSet;
  scope: Scope;
  /** Contenu des fichiers, lu une seule fois pour toutes les règles. */
  content: (path: string) => Promise<string | null>;
  /** Fichiers de tout le projet quand fileSet n'est qu'un sous-ensemble (scan_files, staged, fichier seul) : sert aux conditions `when`. */
  projectFiles?: () => Promise<ScanFile[]>;
}

function finding(rule: Rule, file: string, line: number, snippet: string): Finding {
  const t = rule.text.en;
  if (!t) throw new Error(`rule ${rule.id} has no text`);
  return {
    id: rule.id,
    engine: "house",
    severity: rule.severity,
    category: rule.category,
    title: t.title,
    explanation: t.explanation,
    fix: t.fix,
    file,
    line,
    snippet,
    ...(rule.refs.length > 0 ? { refs: [...rule.refs] } : {}),
  };
}

export async function detect(rule: Rule, input: DetectInput): Promise<Finding[]> {
  switch (rule.detector.type) {
    case "regex":
      return detectRegex(rule as RegexRule, input);
    case "tracked-file":
      return detectTracked(rule, input);
    case "not-gitignored":
      return detectNotIgnored(rule, input);
    case "supabase-rls":
      return detectSupabaseRls(rule, input);
    case "sql-statement":
      return detectSqlStatements(rule, input);
    case "hidden-code":
      return detectHiddenCode(rule, input);
    case "missing-sibling":
      return detectMissingSibling(rule, input);
    case "mcp-config":
      return detectMcpConfig(rule, input);
    case "lookalike-package":
      return detectLookalike(rule, input);
  }
}

/** Dépendances dont le nom ressemble à un paquet très populaire. Données embarquées, aucun accès réseau ; un lockfile ne prouve rien. */
async function detectLookalike(rule: Rule, input: DetectInput): Promise<Finding[]> {
  if (rule.detector.type !== "lookalike-package") return [];
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, rule.detector.files)) continue;
    const base = f.path.split("/").pop() ?? "";
    let eco: Ecosystem = "pypi";
    let parse: (t: string) => Dep[];
    if (base === "package.json") {
      eco = "npm";
      parse = parsePackageJson;
    } else if (base === "pyproject.toml") parse = parsePyproject;
    else if (base.endsWith(".txt")) parse = parseRequirements;
    else continue;
    const text = await input.content(f.path);
    if (text === null) continue;
    const seen = new Set<string>();
    for (const dep of parse(text)) {
      if (seen.has(dep.name)) continue;
      seen.add(dep.name);
      const similar = lookalikes(eco, dep.name);
      if (similar.length === 0) continue;
      const fill = (s: string) =>
        s.replaceAll("{name}", dep.name).replaceAll("{similar}", similar.map((x) => `\`${x}\``).join(", "));
      const fd = finding(rule, f.path, dep.line, `${dep.name} -> ${similar.join(", ")}`);
      out.push({ ...fd, title: fill(fd.title), explanation: fill(fd.explanation), fix: fill(fd.fix) });
    }
  }
  return out;
}

async function detectRegex(rule: RegexRule, input: DetectInput): Promise<Finding[]> {
  const d = rule.detector;
  const rx = new RegExp(d.pattern, `${d.flags}g`);
  const ignore = d.ignoreIf.map((p) => new RegExp(p, d.flags));
  const must = [d.fileMustMatch ?? []].flat().map((p) => new RegExp(p, `m${d.flags}`));
  const unless = d.unlessFile.map((p) => new RegExp(p, `m${d.flags}`));
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, d.files) || matchAny(f.path, d.exclude)) continue;
    if (d.skipUntrackedEnv && isEnvFile(f.path) && !input.fileSet.tracked?.has(f.path)) continue;
    const text = await input.content(f.path);
    if (text === null || !must.every((x) => x.test(text)) || unless.some((x) => x.test(text))) continue;
    const before = out.length;
    const lines = text.split(/\r?\n/);
    let found = false;
    lines.forEach((line, i) => {
      if (line.length > MAX_LINE || (d.firstOnly && found)) return;
      rx.lastIndex = 0;
      for (const m of line.matchAll(rx)) {
        if (ignore.some((x) => x.test(line))) break;
        const secret = d.secretGroup ? m.groups?.[d.secretGroup] : undefined;
        out.push(finding(rule, f.path, i + 1, redactLine(line, secret ? [secret] : [])));
        found = true;
        break; // une fois par ligne suffit
      }
    });
    if (d.lastOnly && out.length - before > 1) out.splice(before, out.length - before - 1);
  }
  return out;
}

async function detectTracked(rule: Rule, input: DetectInput): Promise<Finding[]> {
  if (rule.detector.type !== "tracked-file" || !input.fileSet.tracked) return [];
  const d = rule.detector;
  // Seulement les fichiers du périmètre (projet, dossier, fichier, ou fichiers indexés avec --staged).
  const tracked = input.fileSet.tracked;
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (tracked.has(f.path) && matchAny(f.path, d.files) && !matchAny(f.path, d.exclude)) {
      const x = finding(rule, f.path, 0, "");
      if (d.publicEnvSeverity && isEnvFile(f.path) && onlyPublicVars((await input.content(f.path)) ?? "")) {
        x.severity = d.publicEnvSeverity;
      }
      out.push(x);
    }
  }
  return out;
}

async function detectNotIgnored(rule: Rule, input: DetectInput): Promise<Finding[]> {
  // Question de projet : n'a pas de sens pour un fichier seul, un dossier isolé ou les fichiers indexés.
  if (rule.detector.type !== "not-gitignored" || input.scope !== "project" || input.fileSet.files.length === 0)
    return [];
  const d = rule.detector;
  const { root, gitRoot, files } = input.fileSet;
  if (!files.some((f) => matchAny(f.path, d.when))) return [];
  if (gitRoot) {
    // git décide lui-même, en tenant compte de tous les .gitignore (y compris parents et exclusions globales).
    const r = await run("git", ["check-ignore", "-q", "--no-index", join(root, d.path)], {
      cwd: root,
      timeoutMs: 10_000,
    });
    if (r.code === 0) return [];
    if (r.code !== 1) return [];
  } else {
    const gi = await readText(join(root, ".gitignore"));
    if (gi && gitignoreCovers(gi, d.path)) return [];
  }
  return [finding(rule, ".gitignore", 0, "")];
}

/** Hors dépôt git : lecture simplifiée du .gitignore racine. */
export function gitignoreCovers(gitignore: string, name: string): boolean {
  let covered = false;
  for (const raw of gitignore.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const neg = line.startsWith("!");
    const pat = (neg ? line.slice(1) : line).replace(/^\//, "").replace(/\/$/, "");
    if (matchAny(name, [pat])) covered = !neg;
  }
  return covered;
}

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?((?:"?[\w]+"?\.)?"?[\w]+"?)/gi;
const ENABLE_RLS =
  /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:"?[\w]+"?\.)?"?[\w]+"?)\s+enable\s+row\s+level\s+security/gi;

function tableKey(name: string): { schema: string; table: string } {
  const parts = name.replace(/"/g, "").toLowerCase().split(".");
  return parts.length === 2
    ? { schema: parts[0] as string, table: parts[1] as string }
    : { schema: "public", table: parts[0] as string };
}

/** Tables du schéma public créées dans les migrations sans RLS activé (dans n'importe quelle migration). */
async function detectSupabaseRls(rule: Rule, input: DetectInput): Promise<Finding[]> {
  if (rule.detector.type !== "supabase-rls") return [];
  if (rule.detector.when.length > 0 && !(await anyCondition(rule.detector.when, input))) return [];
  const created: { key: string; file: string; line: number; snippet: string }[] = [];
  const enabled = new Set<string>();
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, rule.detector.files)) continue;
    const sql = await input.content(f.path);
    if (sql === null) continue;
    const clean = sql.replace(/--[^\n]*/g, (c) => " ".repeat(c.length));
    for (const m of clean.matchAll(ENABLE_RLS)) {
      const k = tableKey(m[1] as string);
      enabled.add(`${k.schema}.${k.table}`);
    }
    for (const m of clean.matchAll(CREATE_TABLE)) {
      const k = tableKey(m[1] as string);
      if (k.schema !== "public") continue;
      const line = clean.slice(0, m.index).split("\n").length;
      const snippet = truncate((sql.split("\n")[line - 1] ?? "").trim());
      created.push({ key: `${k.schema}.${k.table}`, file: f.path, line, snippet });
    }
  }
  return created.filter((c) => !enabled.has(c.key)).map((c) => finding(rule, c.file, c.line, c.snippet));
}

/** Instructions SQL maximales analysées en entier (au-delà : seul l'en-tête est évalué, protection contre les expressions trop coûteuses). */
const MAX_STATEMENT = 20_000;

const DOLLAR_TAG = /\$([A-Za-z_][A-Za-z0-9_]{0,30})?\$/y;
const IDENT_CHAR = /[A-Za-z0-9_$]/;

/**
 * Découpe du SQL sur « ; » en respectant commentaires (imbriqués), chaînes (dont E'…'), identifiants "…" et blocs $tag$…$tag$.
 * Parcours linéaire : comme Postgres, un commentaire, une chaîne ou un $tag$ non fermé court jusqu'à la fin du fichier.
 */
export function splitSql(sql: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  let start = 0;
  let line = 1;
  let startLine = 1;
  const n = sql.length;
  const flush = (end: number) => {
    const text = sql.slice(start, end);
    const lead = text.length - text.trimStart().length;
    const lines = text.slice(0, lead).split("\n").length - 1;
    if (text.trim()) out.push({ text, line: startLine + lines });
  };
  /** Avance jusqu'à `stop` en comptant les retours à la ligne. */
  const skipTo = (from: number, stop: number): number => {
    for (let k = from; k < stop; k++) if (sql.charCodeAt(k) === 10) line++;
    return stop;
  };
  let i = 0;
  while (i < n) {
    const c = sql[i] as string;
    const next = sql[i + 1];
    if (c === "\n") {
      line++;
      i++;
    } else if (c === "-" && next === "-") {
      while (i < n && sql[i] !== "\n") i++;
    } else if (c === "/" && next === "*") {
      let depth = 1;
      let k = i + 2;
      while (k < n && depth > 0) {
        if (sql[k] === "/" && sql[k + 1] === "*") {
          depth++;
          k += 2;
        } else if (sql[k] === "*" && sql[k + 1] === "/") {
          depth--;
          k += 2;
        } else k++;
      }
      i = skipTo(i, k);
    } else if (c === "'") {
      const prev = sql[i - 1];
      const escapes = (prev === "E" || prev === "e") && !(i >= 2 && IDENT_CHAR.test(sql[i - 2] as string));
      let k = i + 1;
      while (k < n) {
        if (escapes && sql[k] === "\\") k += 2;
        else if (sql[k] === "'" && sql[k + 1] === "'") k += 2;
        else if (sql[k] === "'") break;
        else k++;
      }
      i = skipTo(i, Math.min(k + 1, n));
    } else if (c === '"') {
      let k = i + 1;
      while (k < n) {
        if (sql[k] === '"' && sql[k + 1] === '"') k += 2;
        else if (sql[k] === '"') break;
        else k++;
      }
      i = skipTo(i, Math.min(k + 1, n));
    } else if (c === "$" && !(i > 0 && IDENT_CHAR.test(sql[i - 1] as string))) {
      DOLLAR_TAG.lastIndex = i;
      const tag = DOLLAR_TAG.exec(sql);
      if (tag) {
        const end = sql.indexOf(tag[0], i + tag[0].length);
        i = skipTo(i, end === -1 ? n : end + tag[0].length);
      } else i++;
    } else if (c === ";") {
      flush(i);
      i++;
      start = i;
      startLine = line;
    } else i++;
  }
  flush(n);
  return out;
}

/** Retire les espaces et commentaires (-- et /* *​/ imbriqués) en tête d'instruction ; renvoie aussi le nombre de lignes passées. */
function stripLeading(text: string): { text: string; lines: number } {
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i] as string;
    if (c === " " || c === "\t" || c === "\r" || c === "\n") i++;
    else if (c === "-" && text[i + 1] === "-") {
      while (i < n && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (text[i] === "/" && text[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (text[i] === "*" && text[i + 1] === "/") {
          depth--;
          i += 2;
        } else i++;
      }
    } else break;
  }
  let lines = 0;
  for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) lines++;
  return { text: text.slice(i), lines };
}

/** Instruction trop longue : on garde l'en-tête (jusqu'à « as $ », « $$ » ou « begin ») et la fin (options après le corps). */
function headerOf(text: string): string {
  if (text.length <= MAX_STATEMENT) return text;
  const head = text.slice(0, MAX_STATEMENT);
  const m = /\bas\s+\$|\$\$|\bbegin\b/i.exec(head);
  return `${m ? head.slice(0, m.index) : head}\n${text.slice(-300)}`;
}

/**
 * Analyse lexicale d'une instruction SQL : retire les commentaires (-- et bloc imbriqué, hors chaînes) et renvoie
 * aussi une copie où le contenu des identifiants "…" et des chaînes ('…', E'…', $$…$$) est remplacé par « _ »
 * (longueur et retours à la ligne conservés), sauf s'il s'agit d'un simple mot (« service_role », « true »).
 * Ainsi un nom de policy comme "for insert" ne passe pas pour la commande de la policy.
 */
export function lexSql(text: string): { clean: string; masked: string } {
  let clean = "";
  let masked = "";
  const n = text.length;
  let i = 0;
  const blank = (t: string) => t.replace(/[^\n]/g, "_");
  while (i < n) {
    const c = text[i] as string;
    if (c === "-" && text[i + 1] === "-") {
      while (i < n && text[i] !== "\n") i++;
      clean += " ";
      masked += " ";
    } else if (c === "/" && text[i + 1] === "*") {
      let depth = 1;
      const from = i;
      i += 2;
      while (i < n && depth > 0) {
        if (text[i] === "/" && text[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (text[i] === "*" && text[i + 1] === "/") {
          depth--;
          i += 2;
        } else i++;
      }
      const gap = text.slice(from, i).replace(/[^\n]/g, " ");
      clean += gap;
      masked += gap;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      // E'…' admet \' ; sinon seule la quote doublée échappe
      const esc = c === "'" && /[eE]/.test(text[i - 1] ?? "") && !/\w/.test(text[i - 2] ?? " ");
      while (j < n) {
        if (esc && text[j] === "\\") j += 2;
        else if (text[j] === c) {
          if (text[j + 1] === c) j += 2;
          else break;
        } else j++;
      }
      const end = Math.min(j + 1, n);
      const raw = text.slice(i, end);
      clean += raw;
      masked += /^\w*$/.test(raw.slice(1, -1)) ? raw : raw[0] + blank(raw.slice(1, -1)) + raw.slice(-1);
      i = end;
    } else if (c === "$" && !/\w/.test(text[i - 1] ?? " ")) {
      const m = /^\$[A-Za-z_]*\$/.exec(text.slice(i, i + 64));
      if (m) {
        const close = text.indexOf(m[0], i + m[0].length);
        const body = text.slice(i + m[0].length, close < 0 ? n : close);
        const tail = close < 0 ? "" : m[0];
        clean += m[0] + body + tail;
        masked += m[0] + blank(body) + tail;
        i += m[0].length + body.length + tail.length;
      } else {
        clean += c;
        masked += c;
        i++;
      }
    } else {
      clean += c;
      masked += c;
      i++;
    }
  }
  return { clean, masked };
}

/** Instructions SQL d'un projet Supabase qui correspondent à un motif (stratégies, fonctions, buckets, vues). */
async function detectSqlStatements(rule: Rule, input: DetectInput): Promise<Finding[]> {
  const d = rule.detector;
  if (d.type !== "sql-statement") return [];
  if (d.when.length > 0 && !(await anyCondition(d.when, input))) return [];
  const main = new RegExp(d.pattern, "i");
  const also = d.also.map((p) => new RegExp(p, "i"));
  const unless = d.unless.map((p) => new RegExp(p, "i"));
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, d.files)) continue;
    const sql = await input.content(f.path);
    if (sql === null) continue;
    for (const s of splitSql(sql)) {
      const lead = stripLeading(s.text.trimStart());
      const { clean: text, masked } = lexSql(headerOf(lead.text));
      if (!main.test(masked) || !also.every((r) => r.test(masked)) || unless.some((r) => r.test(masked))) continue;
      const first = text.trim().split("\n")[0] ?? "";
      out.push(finding(rule, f.path, s.line + lead.lines, truncate(first.trim())));
    }
  }
  return out;
}

const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)/;

/** Un .env dont toutes les variables sont publiques (envoyées au navigateur de toute façon) n'expose rien de plus. */
export function onlyPublicVars(env: string): boolean {
  const keys = env
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map(
      (l) =>
        l
          .replace(/^export\s+/, "")
          .split("=")[0]
          ?.trim() ?? "",
    );
  return keys.length > 0 && keys.every((k) => PUBLIC_PREFIX.test(k));
}

/**
 * Code placé après une très longue suite d'espaces : invisible dans un éditeur sans retour à la ligne.
 * Parcours linéaire (pas d'expression régulière) : ces lignes font souvent des dizaines de milliers de caractères.
 */
export function hiddenCodeColumn(line: string, minSpaces: number): number {
  let run = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if (c === 32 || c === 9) run++;
    else {
      if (run >= minSpaces && i > run) return i;
      run = 0;
    }
  }
  return -1;
}

async function detectHiddenCode(rule: Rule, input: DetectInput): Promise<Finding[]> {
  if (rule.detector.type !== "hidden-code") return [];
  const d = rule.detector;
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, d.files) || matchAny(f.path, d.exclude)) continue;
    const text = await input.content(f.path);
    if (text === null) continue;
    text.split(/\r?\n/).forEach((line, i) => {
      const col = hiddenCodeColumn(line, d.minSpaces);
      if (col < 0) return;
      const visible = line.slice(0, col).trimEnd();
      const hidden = line.slice(col, col + 60);
      out.push(finding(rule, f.path, i + 1, truncate(`${visible} [… ${col - visible.length} espaces …] ${hidden}`)));
    });
  }
  return out;
}

/** Manifeste à la racine du projet sans fichier compagnon (ex. package.json sans lockfile). Projet entier seulement. */
async function detectMissingSibling(rule: Rule, input: DetectInput): Promise<Finding[]> {
  if (rule.detector.type !== "missing-sibling" || input.scope !== "project") return [];
  const d = rule.detector;
  const present = new Set(input.fileSet.files.map((f) => f.path));
  if (d.siblings.some((s) => present.has(s))) return [];
  const must = d.fileMustMatch ? new RegExp(d.fileMustMatch, "m") : null;
  const out: Finding[] = [];
  for (const name of d.files) {
    if (!present.has(name)) continue;
    const text = await input.content(name);
    if (text === null || (must && !must.test(text))) continue;
    out.push(finding(rule, name, 0, ""));
  }
  return out;
}

/** Retire les commentaires // et /* *\/ d'un JSON (JSONC de VS Code), sans toucher aux chaînes. */
export function stripJsonComments(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (inString) {
      out += c;
      if (c === "\\") {
        out += text[i + 1] ?? "";
        i++;
      } else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      const skipped = text.slice(i, end === -1 ? text.length : end + 2);
      out += skipped.replace(/[^\n]/g, " ");
      i = end === -1 ? text.length : end + 1;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

/** Lanceurs de paquets : le paquet est téléchargé au moment du lancement. */
const RUNNERS = new Set(["npx", "bunx", "uvx", "pnpx"]);
/** Spécification de paquet figée : « pkg@1.2.3 », « pkg==1.2.3 », ou archive d'une version précise (…/pkg-1.2.3.tgz). */
function pinnedSpec(spec: string): boolean {
  if (/^https:\/\/\S+\.(?:tgz|tar\.gz|whl)$/.test(spec)) return !/\/latest\//.test(spec) && /\d+\.\d+/.test(spec);
  return /^(?:@[^/]+\/)?[^@=]+(?:@|==)\d/.test(spec);
}

/** Paquet lancé sans version figée ; « --package=x » (npx) désigne le paquet réellement installé. */
function unpinnedPackage(args: string[]): string | null {
  const i = args.findIndex((a) => a === "--package" || a === "-p" || a.startsWith("--package="));
  if (i >= 0) {
    const spec = args[i]?.startsWith("--package=") ? args[i]?.slice(10) : args[i + 1];
    return spec && !pinnedSpec(spec) ? spec : null;
  }
  const pkg = args.find((a) => !a.startsWith("-"));
  if (!pkg || pkg.startsWith(".") || pkg.startsWith("/")) return null;
  return pinnedSpec(pkg) ? null : pkg;
}

/** Valeur écrite en dur qui ressemble à un secret (pas une référence ${VAR} / ${env:VAR} / ${input:x}). */
function inlineSecret(key: string, value: string): boolean {
  if (/\$\{|^\s*$|<[^>]+>|your[_-]|example|changeme|x{6,}/i.test(value)) return false;
  return /(?:key|token|secret|password|passwd|pat|auth)/i.test(key) && value.length >= 12;
}

interface McpServer {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  headers?: unknown;
  url?: unknown;
  serverUrl?: unknown;
}

async function detectMcpConfig(rule: Rule, input: DetectInput): Promise<Finding[]> {
  if (rule.detector.type !== "mcp-config") return [];
  const d = rule.detector;
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, d.files)) continue;
    const text = await input.content(f.path);
    if (text === null) continue;
    let doc: unknown;
    try {
      doc = JSON.parse(stripJsonComments(text));
    } catch {
      continue;
    }
    const root = (doc ?? {}) as Record<string, unknown>;
    const servers = (root.mcpServers ?? root.servers ?? (root.mcp as Record<string, unknown> | undefined)?.servers) as
      | Record<string, McpServer>
      | undefined;
    if (!servers || typeof servers !== "object") continue;
    const lines = text.split(/\r?\n/);
    const lineOf = (needle: string) => {
      const i = lines.findIndex((l) => l.includes(needle));
      return i + 1;
    };
    for (const [name, s] of Object.entries(servers)) {
      if (!s || typeof s !== "object") continue;
      const args = Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === "string") : [];
      const where = lineOf(`"${name}"`);
      if (d.check === "unpinned" && typeof s.command === "string") {
        const cmd = s.command.split(/[\\/]/).pop() ?? "";
        const rest = cmd === "pnpm" && args[0] === "dlx" ? args.slice(1) : RUNNERS.has(cmd) ? args : null;
        const pkg = rest ? unpinnedPackage(rest) : null;
        if (pkg) out.push(finding(rule, f.path, lineOf(`"${pkg}"`) || where, truncate(`${name}: ${cmd} ${pkg}`)));
      }
      if (d.check === "inline-secret") {
        const pairs: [string, string][] = [];
        for (const bag of [s.env, s.headers]) {
          if (bag && typeof bag === "object")
            for (const [k, v] of Object.entries(bag)) if (typeof v === "string") pairs.push([k, v]);
        }
        args.forEach((a, i) => {
          const m = /^--?([\w-]+)=(.+)$/.exec(a);
          if (m) pairs.push([m[1] as string, m[2] as string]);
          else if (i > 0 && /^--?[\w-]*(?:key|token|secret|password)[\w-]*$/i.test(args[i - 1] ?? ""))
            pairs.push([args[i - 1] as string, a]);
        });
        for (const [k, v] of pairs) {
          if (!inlineSecret(k, v)) continue;
          const line = lineOf(v) || where;
          out.push(finding(rule, f.path, line, redactLine(lines[line - 1] ?? "", [v])));
        }
      }
      if (d.check === "insecure-url") {
        const url = typeof s.url === "string" ? s.url : typeof s.serverUrl === "string" ? s.serverUrl : "";
        if (/^http:\/\/(?!(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$))/i.test(url))
          out.push(finding(rule, f.path, lineOf(url) || where, truncate(`${name}: ${url}`)));
      }
    }
  }
  return out;
}

const readCache = new WeakMap<object, Promise<string | null>>();
/** Lecture mémorisée par fichier (objet ScanFile) : une condition ne relit pas le même fichier pour chaque règle. */
function cached(f: { read: () => Promise<string | null> }): Promise<string | null> {
  let p = readCache.get(f);
  if (!p) {
    p = f.read();
    readCache.set(f, p);
  }
  return p;
}

/** Vrai si l'un des fichiers d'une condition existe (et contient son motif, s'il y en a un). */
async function anyCondition(conds: readonly { files: string[]; pattern?: string | undefined }[], input: DetectInput) {
  const files = input.projectFiles ? await input.projectFiles() : input.fileSet.files;
  for (const c of conds) {
    const rx = c.pattern ? toRegExp(c.pattern) : null;
    for (const f of files) {
      if (!matchAny(f.path, c.files)) continue;
      if (!rx) return true;
      const text = input.projectFiles ? await cached(f) : await input.content(f.path);
      if (text !== null && rx.test(text)) return true;
    }
  }
  return false;
}

/** Motif YAML avec drapeaux en tête à la manière de PCRE (« (?im)… ») : JavaScript ne les accepte pas en ligne. */
function toRegExp(p: string): RegExp {
  const m = /^\(\?([im]+)\)/.exec(p);
  return m ? new RegExp(p.slice(m[0].length), m[1]) : new RegExp(p, "m");
}
