// Envoi d'un rapport de scan : MÉTADONNÉES seulement (règle, sévérité, catégorie, chemin, ligne, empreinte).
// Jamais d'extrait de code, de titre ni d'explication : l'API refuse d'ailleurs tout champ en plus.
import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { Finding } from "../core/finding.js";
import type { ScanReport } from "../scan.js";
import { VERSION } from "../version.js";
import { request } from "./client.js";

export interface UploadFinding {
  fingerprint: string;
  ruleId: string;
  severity: string;
  category: string;
  file: string;
  line: number;
}

export interface UploadPayload {
  project: string;
  cliVersion: string;
  score: number;
  findings: UploadFinding[];
}

export interface UploadResult {
  reportId: number;
  projectId: number;
  findings: number;
  new: number;
  fixed: number;
}

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Empreinte stable d'un constat : règle + fichier + contenu de la ligne (déjà masqué, espaces normalisés), sans
 * le numéro de ligne : déplacer du code ne crée pas un « nouveau » constat. Calculée ici, l'extrait ne part pas.
 */
export function fingerprint(f: Pick<Finding, "id" | "file" | "snippet">): string {
  const content = f.snippet.replace(/\s+/g, " ").trim();
  return sha256(`${f.id}\u0000${f.file}\u0000${content}`).slice(0, 32);
}

/** Construit la charge utile. hashPaths : les chemins partent sous forme d'empreinte (sha256:…). */
export function buildPayload(
  report: ScanReport,
  opts: { project?: string | undefined; hashPaths?: boolean } = {},
): UploadPayload {
  const seen = new Set<string>();
  const findings: UploadFinding[] = [];
  for (const f of report.findings) {
    const fp = fingerprint(f);
    if (seen.has(fp)) continue;
    seen.add(fp);
    findings.push({
      fingerprint: fp,
      ruleId: f.id,
      severity: f.severity,
      category: f.category,
      file: opts.hashPaths ? `sha256:${sha256(f.file)}` : f.file,
      line: f.line,
    });
  }
  const project =
    (opts.project ?? basename(report.root))
      .split("")
      .filter((ch) => ch.charCodeAt(0) >= 32)
      .join("")
      .trim()
      .slice(0, 100) || "project";
  return { project, cliVersion: VERSION, score: report.score, findings: findings.slice(0, 5000) };
}

export async function upload(base: string, token: string, payload: UploadPayload): Promise<UploadResult> {
  return request<UploadResult>(base, "/v1/reports", { method: "POST", token, json: payload, timeoutMs: 60_000 });
}
