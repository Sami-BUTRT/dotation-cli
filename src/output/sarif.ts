import { createHash } from "node:crypto";
import type { Finding, Severity } from "../core/finding.js";
import type { ScanReport } from "../scan.js";
import { VERSION } from "../version.js";

// SARIF 2.1.0, lisible par GitHub Code Scanning (upload-sarif).

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};
/** Échelle utilisée par GitHub pour classer les alertes de sécurité (0 à 10). */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };

function ruleOf(f: Finding) {
  return {
    id: f.id,
    name: f.id.replace(/[^A-Za-z0-9]+/g, ""),
    shortDescription: { text: f.title },
    fullDescription: { text: f.explanation },
    help: { text: f.fix || f.explanation, markdown: `**${f.title}**\n\n${f.explanation}\n\n${f.fix}` },
    defaultConfiguration: { level: LEVEL[f.severity] },
    properties: { tags: ["security", f.category, f.engine], "security-severity": SECURITY_SEVERITY[f.severity] },
  };
}

export function toSarif(report: ScanReport) {
  const rules = new Map<string, ReturnType<typeof ruleOf>>();
  for (const f of report.findings) if (!rules.has(f.id)) rules.set(f.id, ruleOf(f));
  const ruleIndex = new Map([...rules.keys()].map((id, i) => [id, i]));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "dotation",
            version: VERSION,
            informationUri: "https://www.dotation.app",
            rules: [...rules.values()],
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.id,
          ruleIndex: ruleIndex.get(f.id) ?? 0,
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.fix}`.trim() },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file, uriBaseId: "%SRCROOT%" },
                ...(f.line > 0 ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
          // Empreinte stable pour que GitHub suive une alerte d'un scan à l'autre (sans le secret : l'extrait est masqué).
          partialFingerprints: {
            primaryLocationLineHash: createHash("sha256")
              .update(`${f.id}|${f.file}|${f.snippet}`)
              .digest("hex")
              .slice(0, 32),
          },
        })),
      },
    ],
  };
}

export function renderSarif(report: ScanReport): string {
  return `${JSON.stringify(toSarif(report), null, 2)}\n`;
}
