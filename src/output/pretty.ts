import pc from "picocolors";
import { SEVERITIES, type Severity } from "../core/finding.js";
import { countBySeverity } from "../core/score.js";
import type { EngineStatus } from "../engines/engine.js";
import { messages } from "../i18n/index.js";
import type { ScanReport } from "../scan.js";

export const DEFAULT_LIMIT = 10;

export interface PrettyOptions {
  all: boolean;
  color: boolean;
  /** Seuil de --fail-on, pour expliquer le code retour. */
  failOn?: Severity;
  failed?: boolean;
}

const ICON: Record<Severity, string> = { critical: "■", high: "▲", medium: "●", low: "·" };

export function renderPretty(report: ScanReport, opts: PrettyOptions): string {
  const m = messages(report.lang);
  const c = pc.createColors(opts.color);
  const paint: Record<Severity, (s: string) => string> = {
    critical: (s) => c.bold(c.red(s)),
    high: c.red,
    medium: c.yellow,
    low: c.dim,
  };
  const out: string[] = [];
  out.push(c.bold(m.report.heading), c.dim(m.report.target(report.target, report.fileCount)), "");

  if (report.fileCount === 0) out.push(m.report.noFiles, "");
  else if (report.findings.length === 0) out.push(c.green(`✓ ${m.report.clean}`), "");

  // Typographie : espace avant les deux-points en français seulement.
  const sep = report.lang === "fr" ? " :" : ":";
  const shown = opts.all ? report.findings : report.findings.slice(0, DEFAULT_LIMIT);
  for (const sev of [...SEVERITIES].reverse()) {
    const group = shown.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    out.push(paint[sev](`${ICON[sev]} ${m.severity[sev].toUpperCase()}`));
    for (const f of group) {
      const where = f.line > 0 ? `${f.file}:${f.line}` : f.file;
      out.push(`  ${c.bold(f.title)}  ${c.dim(where)}`);
      if (f.snippet) out.push(`    ${c.dim("│")} ${c.cyan(f.snippet)}`);
      out.push(`    ${c.dim(`${m.report.why}${sep}`)} ${f.explanation}`);
      if (f.fix) out.push(`    ${c.dim(`${m.report.fix}${sep}`)} ${f.fix}`);
      out.push("");
    }
  }
  const hidden = report.findings.length - shown.length;
  if (hidden > 0) out.push(c.dim(m.report.more(hidden)), "");

  const counts = countBySeverity(report.findings);
  const parts = [...SEVERITIES]
    .reverse()
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${m.severity[s].toLowerCase()}`)
    .join(", ");
  if (parts) out.push(m.report.counts(parts));
  const scoreColor = report.score >= 90 ? c.green : report.score >= 60 ? c.yellow : c.red;
  out.push(c.bold(scoreColor(m.report.score(report.score))), "");

  out.push(c.dim(`${m.report.engines}${sep}`));
  for (const s of report.statuses) out.push(c.dim(`  ${m.engineNames[s.engine]}${sep} ${statusText(s, report.lang)}`));
  if (opts.failed && opts.failOn) out.push("", c.dim(m.report.failOn(m.severity[opts.failOn].toLowerCase())));
  return `${out.join("\n")}\n`;
}

function statusText(s: EngineStatus, lang: ScanReport["lang"]): string {
  const m = messages(lang).report;
  switch (s.state) {
    case "ok":
      return s.detail ? `${m.engineOk(s.count)}${lang === "fr" ? " ;" : ";"} ${s.detail}` : m.engineOk(s.count);
    case "missing":
      return m.engineMissing(s.detail ?? "");
    case "disabled":
      return m.engineDisabled;
    case "timeout":
      return m.engineTimeout(Number(s.detail ?? 60));
    case "failed":
      return m.engineFailed(s.detail ?? "");
  }
}
