import { stat } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { installedPackDirs } from "./cloud/rulepacks.js";
import { BASELINE_PATH, type BaselineEntry, fingerprint, loadBaseline } from "./core/baseline.js";
import { loadConfig } from "./core/config.js";
import { dedupe } from "./core/dedupe.js";
import { collectFiles, type FileSet, type Scope } from "./core/files.js";
import { compareFindings, type Finding } from "./core/finding.js";
import { truncate } from "./core/mask.js";
import { hygieneScore } from "./core/score.js";
import type { Engine, EngineResult, EngineStatus, ScanContext } from "./engines/engine.js";
import { gitleaksEngine } from "./engines/gitleaks.js";
import { houseEngine } from "./engines/house.js";
import { osvEngine } from "./engines/osv.js";
import { semgrepEngine } from "./engines/semgrep.js";
import { messages } from "./i18n/index.js";
import { PROTECTED_RULES } from "./rules/loader.js";

export interface ScanOptions {
  scope?: Scope;
  staged?: boolean;
  timeoutSec?: number;
  /** Moteurs à utiliser ; par défaut tous. Les tests s'en servent pour isoler un moteur. */
  engines?: readonly Engine[];
  /** Baseline : undefined = .dotation/baseline.json s'il existe ; false = ignorée ; chaîne = autre fichier. */
  baseline?: false | string;
  /** Calcule les empreintes de tous les constats (commande `dotation baseline`). */
  collectEntries?: boolean;
}

export interface ScanReport {
  root: string;
  target: string;
  /** A legacy `lang` setting was found in .dotation.yml (ignored). */
  langIgnored?: boolean;
  fileCount: number;
  findings: Finding[];
  statuses: EngineStatus[];
  score: number;
  /** Ce que le projet a fait taire : la sortie le dit toujours (un dépôt piégé écrit lui-même ces réglages). */
  suppressed?: Suppressed;
  /** Constats déjà connus (baseline) : retirés de `findings`, du score et du code retour ; SARIF les rend « unchanged ». */
  baselined?: Finding[];
  /** Empreintes des constats (seulement avec collectEntries). Jamais de valeur de secret. */
  entries?: BaselineEntry[];
}

export interface Suppressed {
  /** Constats retirés par un commentaire dotation-ignore. */
  ignored: number;
  /** Constats retirés par « disable » dans .dotation.yml. */
  disabled: number;
  /** Règles livrées ou des packs remplacées par .dotation/rules. */
  overridden: string[];
  /** Règles protégées que .dotation/rules a tenté de remplacer (tentative ignorée). */
  protectedRejected: string[];
  /** Fichiers de .dotation/rules invalides, ignorés. */
  skippedFiles: { file: string; reason: string }[];
  /** Projet trop grand pour les conditions `when` : évaluées sur les fichiers scannés seulement. */
  projectTooLarge?: boolean;
  /** Constats déjà connus, masqués par la baseline. */
  baseline?: number;
  /** Fichier de baseline utilisé (relatif à la racine quand c'est possible). */
  baselineFile?: string;
  /** Baseline présente mais inutilisable (ignorée). */
  baselineInvalid?: "too-large" | "unreadable" | "malformed" | "too-many-entries";
}

export const ALL_ENGINES: readonly Engine[] = [houseEngine, gitleaksEngine, semgrepEngine, osvEngine];

export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const abs = resolve(target);
  const s = await stat(abs).catch(() => null);
  if (!s) throw new Error(`bad-path:${target}`);
  const configRoot = s.isFile() ? join(abs, "..") : abs;
  const config = await loadConfig(configRoot);
  const scope: Scope = s.isFile() ? "file" : (opts.scope ?? "project");
  const staged = opts.staged ?? false;
  const fileSet = await collectFiles(abs, { scope, staged, excludes: config.exclude });

  const ctx: ScanContext = {
    root: fileSet.root,
    fileSet,
    scope,
    staged,
    msg: messages(),
    config,
    timeoutMs: (opts.timeoutSec ?? config.timeout ?? 60) * 1000,
    // Packs installés (cache local, vérifiés à l'installation) puis règles du projet, qui ont le dernier mot
    // (sauf sur PROTECTED_RULES).
    extraRuleDirs: await installedPackDirs(),
    projectRuleDir: join(fileSet.root, ".dotation", "rules"),
  };

  const engines = opts.engines ?? ALL_ENGINES;
  const results: EngineResult[] = await Promise.all(engines.map((e) => runEngine(e, ctx)));

  const disabled = new Set(config.disable);
  const all = dedupe(results.flatMap((r) => r.findings));
  const kept = all.filter((f) => PROTECTED_RULES.has(f.id) || !disabled.has(f.id));
  const afterIgnore = (await dropIgnored(kept, fileSet)).sort(compareFindings);
  const prints = opts.baseline !== false || opts.collectEntries ? await fingerprints(afterIgnore, fileSet) : [];
  let findings = afterIgnore;
  let baselined: Finding[] | undefined;
  let baselineFile: string | undefined;
  let baselineInvalid: Suppressed["baselineInvalid"];
  if (opts.baseline !== false) {
    const path = opts.baseline ? resolve(opts.baseline) : join(fileSet.root, BASELINE_PATH);
    // Un --baseline explicite est de confiance (choisi par l'utilisateur) ; seule celle du dépôt est confinée.
    const b = await loadBaseline(path, opts.baseline ? undefined : fileSet.root);
    const rel = relative(fileSet.root, path).split("\\").join("/");
    baselineFile = rel.startsWith("..") || isAbsolute(rel) ? basename(path) : rel;
    if (b.state === "invalid") baselineInvalid = b.reason;
    if (b.state === "ok") {
      baselined = [];
      findings = [];
      afterIgnore.forEach((f, i) => {
        // Une baseline vient du dépôt : elle ne masque jamais une règle protégée.
        if (!PROTECTED_RULES.has(f.id) && b.fingerprints.has(prints[i] ?? "")) baselined?.push(f);
        else findings.push(f);
      });
    }
  }
  const notices = results.find((r) => r.status.engine === "house")?.ruleNotices;
  const overridden = notices?.overridden ?? [];
  const protectedRejected = notices?.protectedRejected ?? [];
  const skippedFiles = notices?.skippedFiles ?? [];

  return {
    root: fileSet.root,
    target: abs,
    ...(config.lang !== undefined ? { langIgnored: true } : {}),
    fileCount: fileSet.files.length,
    findings,
    statuses: results.map((r) => r.status),
    score: hygieneScore(findings),
    ...(baselined ? { baselined } : {}),
    ...(opts.collectEntries
      ? {
          entries: afterIgnore.flatMap((f, i) =>
            PROTECTED_RULES.has(f.id) ? [] : [{ ruleId: f.id, file: f.file, fingerprint: prints[i] ?? "" }],
          ),
        }
      : {}),
    suppressed: {
      ignored: kept.length - afterIgnore.length,
      disabled: all.length - kept.length,
      overridden,
      protectedRejected,
      skippedFiles,
      ...(baselined ? { baseline: baselined.length, ...(baselineFile ? { baselineFile } : {}) } : {}),
      ...(baselineInvalid ? { baselineInvalid, ...(baselineFile ? { baselineFile } : {}) } : {}),
      ...(notices?.projectTooLarge ? { projectTooLarge: true } : {}),
    },
  };
}

async function runEngine(engine: Engine, ctx: ScanContext): Promise<EngineResult> {
  try {
    return await engine.scan(ctx);
  } catch (e) {
    // Un moteur ne doit jamais faire tomber le scan entier.
    const reason = e instanceof Error ? e.message.split("\n")[0]?.slice(0, 160) : String(e);
    return { status: { engine: engine.id, state: "failed", count: 0, detail: reason ?? "" }, findings: [] };
  }
}

const IGNORE = /dotation-ignore(?:\s*:?\s*([A-Za-z0-9:/_.,\s-]+))?/;

/** Le commentaire vise-t-il ce constat ? « dotation-ignore » seul : tout ; sinon la liste d'identifiants. */
export function ignoreMatches(line: string, id: string): boolean {
  const m = IGNORE.exec(line);
  if (!m) return false;
  const list = (m[1] ?? "")
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => /^(DOT-|semgrep:|gitleaks:|osv:)/i.test(s));
  return list.length === 0 || list.some((x) => x.toLowerCase() === id.toLowerCase());
}

/** Supprime les constats marqués « dotation-ignore » sur la ligne même ou sur la ligne du dessus. */
async function dropIgnored(findings: Finding[], fileSet: FileSet): Promise<Finding[]> {
  const files = new Map(fileSet.files.map((f) => [f.path, f]));
  const lines = new Map<string, string[] | null>();
  const out: Finding[] = [];
  for (const f of findings) {
    if (f.line > 0) {
      if (!lines.has(f.file)) {
        const text = (await files.get(f.file)?.read()) ?? null;
        lines.set(f.file, text === null ? null : text.split(/\r?\n/));
      }
      const l = lines.get(f.file);
      if (
        l &&
        !PROTECTED_RULES.has(f.id) &&
        (ignoreMatches(l[f.line - 1] ?? "", f.id) || ignoreMatches(l[f.line - 2] ?? "", f.id))
      )
        continue;
    }
    out.push(f);
  }
  return out;
}

/** Empreinte de chaque constat, d'après la ligne réelle du fichier (le extrait affiché est masqué, pas la ligne lue). */
async function fingerprints(findings: Finding[], fileSet: FileSet): Promise<string[]> {
  const files = new Map(fileSet.files.map((f) => [f.path, f]));
  const lines = new Map<string, string[]>();
  const out: string[] = [];
  for (const f of findings) {
    let text = "";
    if (f.line > 0) {
      if (!lines.has(f.file)) lines.set(f.file, ((await files.get(f.file)?.read()) ?? "").split(/\r?\n/));
      text = lines.get(f.file)?.[f.line - 1] ?? "";
    }
    // Extrait masqué (secretGroup, Gitleaks…) : on hache la forme masquée, jamais la ligne brute.
    const redacted = f.category === "secret" || (f.line > 0 && f.snippet !== truncate(text.trim()));
    out.push(redacted ? fingerprint(f.id, f.file, f.snippet, true) : fingerprint(f.id, f.file, text));
  }
  return out;
}
