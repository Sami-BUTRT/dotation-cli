import { countBySeverity } from "../core/score.js";
import type { ScanReport } from "../scan.js";

/** Sortie JSON stable (pour la CI et les scripts). Tous les constats, sans limite d'affichage. */
export function renderJson(report: ScanReport): string {
  return `${JSON.stringify(
    {
      version: 1,
      target: report.target,
      lang: "en",
      files: report.fileCount,
      score: report.score,
      counts: countBySeverity(report.findings),
      findings: report.findings,
      engines: report.statuses,
      suppressed: report.suppressed ?? {
        ignored: 0,
        disabled: 0,
        overridden: [],
        protectedRejected: [],
        skippedFiles: [],
      },
    },
    null,
    2,
  )}\n`;
}
