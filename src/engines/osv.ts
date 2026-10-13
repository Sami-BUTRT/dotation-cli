import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative, sep } from "node:path";
import { hasCommand, run } from "../core/exec.js";
import type { Finding, Severity } from "../core/finding.js";
import type { Messages } from "../i18n/index.js";
import { type Engine, result, shortError } from "./engine.js";

/** Base hors ligne d'OSV-Scanner, propre à dotation (téléchargée par « dotation update-db »). */
export function osvDbDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.DOTATION_OSV_DB ?? join(env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "dotation", "osv");
}

const STALE_DAYS = 7;

const LOCKFILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "uv.lock",
  "go.mod",
  "Cargo.lock",
  "composer.lock",
  "Gemfile.lock",
]);

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  affected?: { package?: { name?: string }; ranges?: { events?: { fixed?: string }[] }[] }[];
}
interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities?: OsvVuln[];
  groups?: { ids: string[]; max_severity?: string }[];
}
interface OsvOutput {
  results?: { source: { path: string }; packages?: OsvPackage[] }[];
}

export function cvssToSeverity(score: string | undefined): Severity {
  const n = Number.parseFloat(score ?? "");
  if (Number.isNaN(n)) return "medium";
  if (n >= 9) return "critical";
  if (n >= 7) return "high";
  if (n >= 4) return "medium";
  return "low";
}

function fixedVersion(v: OsvVuln, pkg: string): string | null {
  for (const a of v.affected ?? []) {
    if (a.package?.name && a.package.name !== pkg) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) return e.fixed;
  }
  return null;
}

/** Compare deux versions « 1.2.10 » > « 1.2.9 » (suffisant pour choisir la plus haute version corrigée). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/).map((x) => Number.parseInt(x, 10));
  const pb = b.split(/[.+-]/).map((x) => Number.parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (Number.isNaN(pa[i] ?? 0) ? 0 : (pa[i] ?? 0)) - (Number.isNaN(pb[i] ?? 0) ? 0 : (pb[i] ?? 0));
    if (d !== 0) return d;
  }
  return 0;
}

const RANKS = ["low", "medium", "high", "critical"] as const;

/**
 * Un constat par paquet vulnérable (et non par identifiant CVE/GHSA) : le geste à faire est le même,
 * mettre ce paquet à jour vers la plus haute des versions corrigées.
 */
export function parseOsv(json: string, root: string, msg: Messages): Finding[] {
  const data = JSON.parse(json || "{}") as OsvOutput;
  const out: Finding[] = [];
  for (const res of data.results ?? []) {
    const file = relative(root, res.source.path).split(sep).join("/");
    for (const p of res.packages ?? []) {
      const vulns = new Map((p.vulnerabilities ?? []).map((v) => [v.id, v]));
      const groups: { ids: string[]; max_severity?: string }[] =
        p.groups ?? (p.vulnerabilities ?? []).map((v) => ({ ids: [v.id] }));
      if (groups.length === 0) continue;
      let worst = 0;
      let fixed: string | null = null;
      let summary = "";
      const ids: string[] = [];
      for (const g of groups) {
        const sorted = [...g.ids].sort((a, b) => Number(b.startsWith("GHSA")) - Number(a.startsWith("GHSA")));
        const main = sorted.map((id) => vulns.get(id)).find(Boolean);
        ids.push(sorted[0] ?? "?");
        worst = Math.max(worst, RANKS.indexOf(cvssToSeverity(g.max_severity)));
        if (!summary && main?.summary) summary = main.summary.replace(/\.$/, "");
        const fx = main ? fixedVersion(main, p.package.name) : null;
        if (fx && (!fixed || compareVersions(fx, fixed) > 0)) fixed = fx;
      }
      out.push({
        id: `osv:${p.package.ecosystem}/${p.package.name}`,
        engine: "osv",
        severity: RANKS[worst] ?? "medium",
        category: "dependency",
        title: msg.osv.title(p.package.name, p.package.version, ids.length),
        explanation: msg.osv.explanation(summary, ids),
        fix: msg.osv.fix(p.package.name, fixed),
        file,
        line: 0,
        snippet: `${p.package.ecosystem} ${p.package.name}@${p.package.version}`,
      });
    }
  }
  return out;
}

async function dbAgeDays(dir: string): Promise<number | null> {
  try {
    let newest = 0;
    const walk = async (d: string) => {
      for (const e of await readdir(d, { withFileTypes: true })) {
        const p = join(d, e.name);
        if (e.isDirectory()) await walk(p);
        else newest = Math.max(newest, (await stat(p)).mtimeMs);
      }
    };
    await walk(dir);
    return newest === 0 ? null : Math.floor((Date.now() - newest) / 86_400_000);
  } catch {
    return null;
  }
}

export const osvEngine: Engine = {
  id: "osv",
  async scan(ctx) {
    if (ctx.config.engines.osv === false) return result("osv", "disabled");
    if (!(await hasCommand("osv-scanner", ["--version"]))) return result("osv", "missing", [], ctx.msg.install.osv);
    const lockfiles = ctx.fileSet.files.filter((f) => LOCKFILES.has(f.path.split("/").pop() ?? ""));
    if (lockfiles.length === 0) return result("osv", "ok");

    const db = osvDbDir();
    const age = await dbAgeDays(db);
    if (age === null) return result("osv", "missing", [], ctx.msg.osv.dbMissing);

    const args = [
      "scan",
      "source",
      "--offline",
      "--offline-vulnerabilities",
      "--format",
      "json",
      "--verbosity",
      "error",
    ];
    for (const f of lockfiles) args.push("--lockfile", join(ctx.root, f.path));
    const r = await run("osv-scanner", args, {
      cwd: ctx.root,
      timeoutMs: ctx.timeoutMs,
      env: { ...process.env, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: db },
    });
    if (r.timedOut) return result("osv", "timeout", [], String(ctx.timeoutMs / 1000));
    // 0 : rien ; 1 : vulnérabilités trouvées ; 128 : aucun paquet ; autre : erreur.
    if (r.code === 128) return result("osv", "ok");
    if (r.code !== 0 && r.code !== 1) return result("osv", "failed", [], shortError(r.stderr));
    const findings = parseOsv(r.stdout, ctx.root, ctx.msg);
    return result("osv", "ok", findings, age > STALE_DAYS ? ctx.msg.osv.dbStale(age) : undefined);
  },
};

/** Télécharge la base pour les écosystèmes présents dans `target` (seule opération réseau de dotation). */
export async function updateOsvDb(target: string, timeoutMs = 600_000): Promise<{ ok: boolean; error?: string }> {
  if (!(await hasCommand("osv-scanner", ["--version"]))) return { ok: false, error: "osv-scanner absent" };
  const r = await run(
    "osv-scanner",
    [
      "scan",
      "source",
      "-r",
      "--offline-vulnerabilities",
      "--download-offline-databases",
      "--format",
      "json",
      "--verbosity",
      "error",
      target,
    ],
    { timeoutMs, env: { ...process.env, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: osvDbDir() } },
  );
  return r.code === 0 || r.code === 1 || r.code === 128 ? { ok: true } : { ok: false, error: shortError(r.stderr) };
}
