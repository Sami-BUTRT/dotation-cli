import { createHash } from "node:crypto";
import type { Finding, Severity } from "../core/finding.js";
import { refUrl, sarifTag } from "../core/refs.js";
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
  const refs = f.refs ?? [];
  const links = refs.map((r) => `[${r}](${refUrl(r)})`).join(" · ");
  return {
    id: f.id,
    name: f.id.replace(/[^A-Za-z0-9]+/g, ""),
    shortDescription: { text: f.title },
    fullDescription: { text: f.explanation },
    help: {
      text: f.fix || f.explanation,
      markdown: `**${f.title}**\n\n${f.explanation}\n\n${f.fix}${links ? `\n\n${links}` : ""}`,
    },
    defaultConfiguration: { level: LEVEL[f.severity] },
    properties: {
      tags: ["security", f.category, f.engine, ...refs.map(sarifTag)],
      "security-severity": SECURITY_SEVERITY[f.severity],
    },
  };
}

export function toSarif(report: ScanReport) {
  const rules = new Map<string, ReturnType<typeof ruleOf>>();
  const baselinedSet = new Set(report.baselined ?? []);
  const all = [...report.findings, ...baselinedSet];
  for (const f of all) if (!rules.has(f.id)) rules.set(f.id, ruleOf(f));
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
        results: all.map((f) => ({
          // Baseline : les constats connus restent dans le rapport, marqués « unchanged » (norme SARIF, § 3.27.24).
          ...(report.baselined ? { baselineState: baselinedSet.has(f) ? "unchanged" : "new" } : {}),
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
