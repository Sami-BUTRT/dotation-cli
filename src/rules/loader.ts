import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "yaml";
import { packagePath } from "../paths.js";
import { type Rule, RuleSchema } from "./schema.js";

export const BUILTIN_RULES_DIR = packagePath("rules");

export class RuleError extends Error {}

async function listRuleFiles(dir: string): Promise<string[]> {
  try {
    return (await readdir(dir)).filter((n) => /\.ya?ml$/.test(n)).sort();
  } catch {
    return [];
  }
}

async function loadRuleFile(dir: string, name: string): Promise<Rule[]> {
  const raw: unknown = parse(await readFile(join(dir, name), "utf8"));
  const docs = Array.isArray(raw) ? raw : [raw];
  const rules: Rule[] = [];
  for (const doc of docs) {
    const r = RuleSchema.safeParse(doc);
    if (!r.success) {
      throw new RuleError(
        `${join(dir, name)} : ${r.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ")}`,
      );
    }
    checkRegexes(r.data, name);
    rules.push(r.data);
  }
  return rules;
}

/** Charge et valide toutes les règles d'un dossier (.yml / .yaml). Un dossier absent donne une liste vide. */
export async function loadRuleDir(dir: string): Promise<Rule[]> {
  const rules: Rule[] = [];
  for (const name of await listRuleFiles(dir)) rules.push(...(await loadRuleFile(dir, name)));
  return rules;
}

export interface SkippedRuleFile {
  file: string;
  reason: string;
}

/** Règles du projet (sans confiance) : un fichier invalide est écarté et signalé, il ne bloque pas les autres. */
async function loadProjectRuleDir(dir: string): Promise<{ rules: Rule[]; skipped: SkippedRuleFile[] }> {
  const rules: Rule[] = [];
  const skipped: SkippedRuleFile[] = [];
  for (const name of await listRuleFiles(dir)) {
    try {
      rules.push(...(await loadRuleFile(dir, name)));
    } catch (e) {
      const reason = (e instanceof Error ? e.message : String(e)).split("\n")[0] ?? "";
      skipped.push({ file: name, reason: reason.replace(join(dir, name), name).slice(0, 160) });
    }
  }
  return { rules, skipped };
}

function checkRegexes(rule: Rule, file: string) {
  const d = rule.detector;
  if (d.type === "missing-sibling" && d.fileMustMatch) {
    try {
      new RegExp(d.fileMustMatch, "m");
    } catch (e) {
      throw new RuleError(`${file} (${rule.id}): invalid pattern: ${(e as Error).message}`);
    }
  }
  if (d.type === "supabase-rls") {
    for (const c of d.when) {
      try {
        if (c.pattern) new RegExp(c.pattern.replace(/^\(\?[im]+\)/, ""));
      } catch (e) {
        throw new RuleError(`${file} (${rule.id}): invalid pattern: ${(e as Error).message}`);
      }
    }
  }
  if (d.type === "sql-statement") {
    for (const p of [d.pattern, ...d.also, ...d.unless]) {
      try {
        new RegExp(p, "i");
      } catch (e) {
        throw new RuleError(`${file} (${rule.id}): invalid pattern: ${(e as Error).message}`);
      }
    }
  }
  if (d.type !== "regex") return;
  for (const p of [d.pattern, ...d.ignoreIf, ...d.unlessFile, ...[d.fileMustMatch ?? []].flat()]) {
    try {
      new RegExp(p, d.flags);
    } catch (e) {
      throw new RuleError(`${file} (${rule.id}): invalid pattern: ${(e as Error).message}`);
    }
  }
  if (d.secretGroup && !d.pattern.includes(`(?<${d.secretGroup}>`)) {
    throw new RuleError(`${file} (${rule.id}): group "${d.secretGroup}" missing from the pattern`);
  }
}

/** Règles livrées + règles du projet ; une règle du projet remplace une règle livrée de même id. */
/**
 * Règles qu'un projet ne peut ni remplacer, ni désactiver, ni ignorer : elles visent les dépôts piégés, dont le contenu
 * (commentaires, .dotation.yml, .dotation/rules) est écrit par l'attaquant.
 */
export const PROTECTED_RULES: ReadonlySet<string> = new Set(["DOT-SEC-007"]);

export interface RuleSet {
  rules: Rule[];
  /** Identifiants des règles qui viennent de .dotation/rules (textes écrits par l'auteur du dépôt). */
  fromProject: Set<string>;
  /** Règles livrées (ou des packs) remplacées par une règle du projet de même identifiant. */
  overridden: string[];
  /** Règles protégées que le projet a tenté de remplacer : tentative ignorée. */
  protectedRejected: string[];
  /** Fichiers de .dotation/rules invalides, ignorés. */
  skipped: SkippedRuleFile[];
}

/** Règles livrées, puis packs (vérifiés), puis règles du projet : le projet a le dernier mot, sauf sur PROTECTED_RULES. */
export async function loadRuleSet(packDirs: readonly string[], projectDir?: string): Promise<RuleSet> {
  const byId = new Map<string, Rule>();
  for (const dir of [BUILTIN_RULES_DIR, ...packDirs]) {
    for (const r of await loadRuleDir(dir)) byId.set(r.id, r);
  }
  const overridden: string[] = [];
  const protectedRejected: string[] = [];
  const fromProject = new Set<string>();
  const project = projectDir ? await loadProjectRuleDir(projectDir) : { rules: [], skipped: [] };
  for (const r of project.rules) {
    if (byId.has(r.id)) {
      if (PROTECTED_RULES.has(r.id)) {
        if (!protectedRejected.includes(r.id)) protectedRejected.push(r.id);
        continue;
      }
      overridden.push(r.id);
    }
    byId.set(r.id, r);
    fromProject.add(r.id);
  }
  return {
    rules: [...byId.values()],
    fromProject,
    overridden: overridden.sort(),
    protectedRejected: protectedRejected.sort(),
    skipped: project.skipped,
  };
}

export async function loadRules(extraDirs: readonly string[]): Promise<Rule[]> {
  return (await loadRuleSet(extraDirs)).rules;
}
