import type { Finding, Severity } from "./finding.js";

/** Pénalité par problème ; le score part de 100 et ne descend pas sous 0. */
export const PENALTY: Readonly<Record<Severity, number>> = { critical: 25, high: 10, medium: 4, low: 1 };

/**
 * Les dépendances vulnérables comptent au plus pour DEPENDENCY_CAP points : souvent transitives et corrigées
 * d'un seul « npm update », elles ne doivent pas noyer les problèmes de ton propre code.
 */
export const DEPENDENCY_CAP = 25;

export function hygieneScore(findings: readonly Finding[]): number {
  let own = 0;
  let deps = 0;
  for (const f of findings) {
    if (f.category === "dependency") deps += PENALTY[f.severity];
    else own += PENALTY[f.severity];
  }
  return Math.max(0, 100 - own - Math.min(deps, DEPENDENCY_CAP));
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
