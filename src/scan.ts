import { stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { installedPackDirs } from "./cloud/rulepacks.js";
import { loadConfig } from "./core/config.js";
import { dedupe } from "./core/dedupe.js";
import { collectFiles, type FileSet, type Scope } from "./core/files.js";
import { compareFindings, type Finding } from "./core/finding.js";
import { hygieneScore } from "./core/score.js";
import type { Engine, EngineResult, EngineStatus, ScanContext } from "./engines/engine.js";
import { gitleaksEngine } from "./engines/gitleaks.js";
import { houseEngine } from "./engines/house.js";
import { osvEngine } from "./engines/osv.js";
import { semgrepEngine } from "./engines/semgrep.js";
import { detectLang, type Lang, messages } from "./i18n/index.js";

export interface ScanOptions {
  scope?: Scope;
  staged?: boolean;
  lang?: Lang;
  timeoutSec?: number;
  /** Moteurs à utiliser ; par défaut tous. Les tests s'en servent pour isoler un moteur. */
  engines?: readonly Engine[];
}

export interface ScanReport {
  root: string;
  target: string;
  lang: Lang;
  fileCount: number;
  findings: Finding[];
  statuses: EngineStatus[];
  score: number;
}

export const ALL_ENGINES: readonly Engine[] = [houseEngine, gitleaksEngine, semgrepEngine, osvEngine];

export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const abs = resolve(target);
  const s = await stat(abs).catch(() => null);
  if (!s) throw new Error(`bad-path:${target}`);
  const configRoot = s.isFile() ? join(abs, "..") : abs;
  const config = await loadConfig(configRoot);
  const lang = opts.lang ?? config.lang ?? detectLang();
  const scope: Scope = s.isFile() ? "file" : (opts.scope ?? "project");
  const staged = opts.staged ?? false;
  const fileSet = await collectFiles(abs, { scope, staged, excludes: config.exclude });

  const ctx: ScanContext = {
    root: fileSet.root,
    fileSet,
    scope,
    staged,
    lang,
    msg: messages(lang),
    config,
    timeoutMs: (opts.timeoutSec ?? config.timeout ?? 60) * 1000,
    // Packs installés (cache local, vérifiés à l'installation) puis règles du projet, qui ont le dernier mot.
    extraRuleDirs: [...(await installedPackDirs()), join(fileSet.root, ".dotation", "rules")],
  };

  const engines = opts.engines ?? ALL_ENGINES;
  const results: EngineResult[] = await Promise.all(engines.map((e) => runEngine(e, ctx)));

  const disabled = new Set(config.disable);
  const kept = dedupe(results.flatMap((r) => r.findings)).filter((f) => !disabled.has(f.id));
  const findings = (await dropIgnored(kept, fileSet)).sort(compareFindings);

  return {
    root: fileSet.root,
    target: abs,
    lang,
    fileCount: fileSet.files.length,
    findings,
    statuses: results.map((r) => r.status),
    score: hygieneScore(findings),
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
      if (l && (ignoreMatches(l[f.line - 1] ?? "", f.id) || ignoreMatches(l[f.line - 2] ?? "", f.id))) continue;
    }
    out.push(f);
  }
  return out;
}
