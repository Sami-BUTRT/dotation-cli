import { type Finding, severityRank } from "./finding.js";

// Ordre de préférence à sévérité égale : nos règles ont les textes les plus pédagogiques.
const ENGINE_PREF = { house: 0, semgrep: 1, gitleaks: 2, osv: 3 } as const;

/**
 * Supprime les doublons : même fichier, même ligne, même catégorie (ex. un secret vu par Gitleaks et par une règle maison).
 * Garde le plus grave ; à égalité, celui du moteur préféré.
 */
export function dedupe(findings: readonly Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    const key = f.category === "dependency" ? `${f.file}|${f.id}` : `${f.file}|${f.line}|${f.category}`;
    const cur = best.get(key);
    if (!cur || better(f, cur)) best.set(key, f);
  }
  return [...best.values()];
}

function better(a: Finding, b: Finding): boolean {
  const d = severityRank(a.severity) - severityRank(b.severity);
  if (d !== 0) return d > 0;
  return ENGINE_PREF[a.engine] < ENGINE_PREF[b.engine];
}
