import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "yaml";
import { packagePath } from "../paths.js";
import { type Rule, RuleSchema } from "./schema.js";

export const BUILTIN_RULES_DIR = packagePath("rules");

export class RuleError extends Error {}

/** Charge et valide toutes les règles d'un dossier (.yml / .yaml). Un dossier absent donne une liste vide. */
export async function loadRuleDir(dir: string): Promise<Rule[]> {
  let names: string[];
  try {
    names = (await readdir(dir)).filter((n) => /\.ya?ml$/.test(n)).sort();
  } catch {
    return [];
  }
  const rules: Rule[] = [];
  for (const name of names) {
    const raw: unknown = parse(await readFile(join(dir, name), "utf8"));
    const docs = Array.isArray(raw) ? raw : [raw];
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
  }
  return rules;
}

function checkRegexes(rule: Rule, file: string) {
  const d = rule.detector;
  if (d.type !== "regex") return;
  for (const p of [d.pattern, ...d.ignoreIf, ...(d.fileMustMatch ? [d.fileMustMatch] : [])]) {
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
export async function loadRules(extraDirs: readonly string[]): Promise<Rule[]> {
  const byId = new Map<string, Rule>();
  for (const dir of [BUILTIN_RULES_DIR, ...extraDirs]) {
    for (const r of await loadRuleDir(dir)) byId.set(r.id, r);
  }
  return [...byId.values()];
}
