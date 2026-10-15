import { hasCommand, run } from "../core/exec.js";
import { DEFAULT_EXCLUDES } from "../core/files.js";
import { type Finding, isSeverity, type Severity } from "../core/finding.js";
import { truncate } from "../core/mask.js";
import { isRef } from "../core/refs.js";
import type { Texts } from "../i18n/index.js";
import { packagePath } from "../paths.js";
import { type Engine, result, shortError } from "./engine.js";

export const SEMGREP_RULES_DIR = packagePath("engines/semgrep");
const MAX_TARGETS = 2000;

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  extra: {
    severity?: string;
    message?: string;
    lines?: string;
    metadata?: {
      dotation?: { severity?: string; category?: string; refs?: unknown } & { en?: Texts };
    };
  };
}

const SEVERITY_FALLBACK: Record<string, Severity> = { ERROR: "high", WARNING: "medium", INFO: "low" };

// Aucune donnée ne sort : pas de métriques, pas de vérification de version, pas de registre.
export const SEMGREP_ENV = {
  SEMGREP_SEND_METRICS: "off",
  SEMGREP_ENABLE_VERSION_CHECK: "0",
} as const;

export function semgrepEnv(): NodeJS.ProcessEnv {
  return { ...process.env, ...SEMGREP_ENV };
}

function refsOf(v: unknown): { refs?: string[] } {
  const refs = Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && isRef(x)) : [];
  return refs.length > 0 ? { refs } : {};
}

export function parseSemgrep(json: string): Finding[] {
  const data = JSON.parse(json) as { results?: SemgrepResult[] };
  return (data.results ?? []).map((r) => {
    const meta = r.extra.metadata?.dotation ?? {};
    const texts = (meta as { en?: Texts }).en;
    const sev =
      meta.severity && isSeverity(meta.severity)
        ? meta.severity
        : (SEVERITY_FALLBACK[r.extra.severity ?? ""] ?? "medium");
    const shortId = r.check_id.split(".").pop() ?? r.check_id;
    const lines = r.extra.lines && r.extra.lines !== "requires login" ? r.extra.lines : "";
    return {
      id: `semgrep:${shortId}`,
      engine: "semgrep",
      severity: sev,
      category: meta.category === "access" || meta.category === "config" ? meta.category : "code",
      title: texts?.title ?? r.extra.message ?? shortId,
      explanation: texts?.explanation ?? r.extra.message ?? "",
      fix: texts?.fix ?? "",
      file: r.path.replace(/^\.\//, ""),
      line: r.start.line,
      snippet: truncate((lines.split("\n")[0] ?? "").trim()),
      ...refsOf(meta.refs),
    };
  });
}

export const semgrepEngine: Engine = {
  id: "semgrep",
  async scan(ctx) {
    if (ctx.config.engines.semgrep === false) return result("semgrep", "disabled");
    // Même la vérification de présence passe par SEMGREP_ENV : « semgrep --version » contacte sinon les serveurs de Semgrep.
    if (!(await hasCommand("semgrep", ["--version"], semgrepEnv())))
      return result("semgrep", "missing", [], ctx.msg.install.semgrep);
    const targets = ctx.fileSet.files.map((f) => f.path).filter((p) => /\.(m?[jt]sx?|cjs|py|vue|svelte)$/.test(p));
    if (targets.length === 0) return result("semgrep", "ok");

    const timeoutSec = Math.max(5, Math.floor(ctx.timeoutMs / 1000));
    const args = [
      "scan",
      "--config",
      SEMGREP_RULES_DIR,
      "--json",
      "--quiet",
      "--metrics=off",
      "--disable-version-check",
      "--no-git-ignore",
      "--timeout",
      String(Math.min(30, timeoutSec)),
      "--max-memory",
      "1500",
      "--jobs",
      "1",
      ...DEFAULT_EXCLUDES.flatMap((g) => ["--exclude", g.replace(/^\*\*\//, "").replace(/\/\*\*$/, "")]),
      "--",
      // Les fichiers exacts de notre liste (mêmes exclusions et même périmètre que les autres moteurs) ;
      // au-delà de MAX_TARGETS, la ligne de commande deviendrait trop longue : on passe le dossier.
      ...(targets.length > MAX_TARGETS ? ["."] : targets),
    ];
    const r = await run("semgrep", args, {
      cwd: ctx.root,
      timeoutMs: ctx.timeoutMs,
      env: semgrepEnv(),
    });
    if (r.timedOut) return result("semgrep", "timeout", [], String(timeoutSec));
    // 0 : rien ; 1 : résultats trouvés ; au-delà : erreur.
    if (r.code !== 0 && r.code !== 1) return result("semgrep", "failed", [], shortError(r.stderr || r.stdout));
    // Semgrep peut répondre 0 avec une configuration invalide : ses erreurs sont dans le JSON.
    const errors = (JSON.parse(r.stdout || "{}") as { errors?: { level?: string; message?: string }[] }).errors ?? [];
    const fatal = errors.find((e) => e.level === "error" && /config|YAML|rule/i.test(e.message ?? ""));
    if (fatal) return result("semgrep", "failed", [], shortError(fatal.message ?? ""));
    const findings = parseSemgrep(r.stdout);
    // Semgrep OSS n'envoie plus la ligne sans connexion à son service : on la relit dans nos fichiers.
    const files = new Map(ctx.fileSet.files.map((f) => [f.path, f]));
    const texts = new Map<string, string | null>();
    for (const f of findings) {
      if (f.snippet) continue;
      if (!texts.has(f.file)) texts.set(f.file, (await files.get(f.file)?.read()) ?? null);
      f.snippet = truncate((texts.get(f.file)?.split(/\r?\n/)[f.line - 1] ?? "").trim());
    }
    return result("semgrep", "ok", findings);
  },
};
