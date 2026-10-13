import { join } from "node:path";
import { run } from "../core/exec.js";
import { type FileSet, isEnvFile, readText, type Scope } from "../core/files.js";
import type { Finding } from "../core/finding.js";
import { matchAny } from "../core/glob.js";
import { redactLine, truncate } from "../core/mask.js";
import { type Lang, pick } from "../i18n/index.js";
import type { RegexRule, Rule } from "./schema.js";

/** Lignes plus longues ignorées : fichiers minifiés, et protection contre les expressions trop coûteuses. */
const MAX_LINE = 2000;

export interface DetectInput {
  fileSet: FileSet;
  scope: Scope;
  lang: Lang;
  /** Contenu des fichiers, lu une seule fois pour toutes les règles. */
  content: (path: string) => Promise<string | null>;
}

function finding(rule: Rule, lang: Lang, file: string, line: number, snippet: string): Finding {
  const t = pick(rule.text, lang);
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
    case "hidden-code":
      return detectHiddenCode(rule, input);
  }
}

async function detectRegex(rule: RegexRule, input: DetectInput): Promise<Finding[]> {
  const d = rule.detector;
  const rx = new RegExp(d.pattern, `${d.flags}g`);
  const ignore = d.ignoreIf.map((p) => new RegExp(p, d.flags));
  const must = d.fileMustMatch ? new RegExp(d.fileMustMatch, "m") : null;
  const out: Finding[] = [];
  for (const f of input.fileSet.files) {
    if (!matchAny(f.path, d.files) || matchAny(f.path, d.exclude)) continue;
    if (d.skipUntrackedEnv && isEnvFile(f.path) && !input.fileSet.tracked?.has(f.path)) continue;
    const text = await input.content(f.path);
    if (text === null || (must && !must.test(text))) continue;
    const lines = text.split(/\r?\n/);
    lines.forEach((line, i) => {
      if (line.length > MAX_LINE) return;
      rx.lastIndex = 0;
      for (const m of line.matchAll(rx)) {
        if (ignore.some((x) => x.test(line))) break;
        const secret = d.secretGroup ? m.groups?.[d.secretGroup] : undefined;
        out.push(finding(rule, input.lang, f.path, i + 1, redactLine(line, secret ? [secret] : [])));
        break; // une fois par ligne suffit
      }
    });
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
      const x = finding(rule, input.lang, f.path, 0, "");
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
  return [finding(rule, input.lang, ".gitignore", 0, "")];
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
  return created.filter((c) => !enabled.has(c.key)).map((c) => finding(rule, input.lang, c.file, c.line, c.snippet));
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
      out.push(
        finding(
          rule,
          input.lang,
          f.path,
          i + 1,
          truncate(`${visible} [… ${col - visible.length} espaces …] ${hidden}`),
        ),
      );
    });
  }
  return out;
}
