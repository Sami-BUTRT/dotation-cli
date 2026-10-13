import { countBySeverity } from "../core/score.js";
import type { ScanReport } from "../scan.js";

/** Sortie JSON stable (pour la CI et les scripts). Tous les constats, sans limite d'affichage. */
export function renderJson(report: ScanReport): string {
  return `${JSON.stringify(
    {
      version: 1,
      target: report.target,
      lang: report.lang,
      files: report.fileCount,
      score: report.score,
      counts: countBySeverity(report.findings),
      findings: report.findings,
      engines: report.statuses,
    },
    null,
    2,
  )}\n`;
}
