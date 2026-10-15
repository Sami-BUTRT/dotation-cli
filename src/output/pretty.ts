import pc from "picocolors";
import { SEVERITIES, type Severity } from "../core/finding.js";
import { countBySeverity } from "../core/score.js";
import { safeLine } from "../core/terminal.js";
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
  const m = messages();
  const c = pc.createColors(opts.color);
  const paint: Record<Severity, (s: string) => string> = {
    critical: (s) => c.bold(c.red(s)),
    high: c.red,
    medium: c.yellow,
    low: c.dim,
  };
  const out: string[] = [];
  out.push(c.bold(m.report.heading), c.dim(m.report.target(safeLine(report.target), report.fileCount)), "");

  if (report.fileCount === 0) out.push(m.report.noFiles, "");
  else if (report.findings.length === 0) out.push(c.green(`✓ ${m.report.clean}`), "");

  const sep = ":";
  const shown = opts.all ? report.findings : report.findings.slice(0, DEFAULT_LIMIT);
  for (const sev of [...SEVERITIES].reverse()) {
    const group = shown.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    out.push(paint[sev](`${ICON[sev]} ${m.severity[sev].toUpperCase()}`));
    for (const f of group) {
      // Tout ce qui suit peut venir du dépôt analysé (chemins, extraits, textes des règles du projet).
      const where = safeLine(f.line > 0 ? `${f.file}:${f.line}` : f.file);
      const own = f.projectRule ? c.dim(` (${m.report.projectRule})`) : "";
      out.push(`  ${c.bold(safeLine(f.title))}  ${c.dim(where)}${own}`);
      if (f.snippet) out.push(`    ${c.dim("│")} ${c.cyan(safeLine(f.snippet))}`);
      out.push(`    ${c.dim(`${m.report.why}${sep}`)} ${safeLine(f.explanation)}`);
      if (f.fix) out.push(`    ${c.dim(`${m.report.fix}${sep}`)} ${safeLine(f.fix)}`);
      if (f.refs?.length) out.push(`    ${c.dim(`${m.report.refs}${sep} ${f.refs.join(" · ")}`)}`);
      out.push("");
    }
  }
  const hidden = report.findings.length - shown.length;
  if (hidden > 0) out.push(c.dim(m.report.more(hidden)), "");
  const sup = report.suppressed;
  if (sup && (sup.ignored > 0 || sup.disabled > 0 || sup.overridden.length > 0))
    out.push(c.yellow(safeLine(m.report.suppressed(sup.ignored, sup.disabled, sup.overridden))), "");
  if (sup && sup.protectedRejected.length > 0)
    out.push(c.yellow(safeLine(m.report.protectedRejected(sup.protectedRejected))), "");
  if (sup?.baseline)
    out.push(
      c.yellow(safeLine(m.report.baselineHidden(sup.baseline, sup.baselineFile ?? ".dotation/baseline.json"))),
      "",
    );
  if (sup?.baselineInvalid)
    out.push(
      c.yellow(safeLine(m.report.baselineInvalid(sup.baselineInvalid, sup.baselineFile ?? ".dotation/baseline.json"))),
      "",
    );
  if (sup?.projectTooLarge) out.push(c.yellow(safeLine(m.report.projectTooLarge)), "");
  for (const s of sup?.skippedFiles ?? []) out.push(c.yellow(safeLine(m.report.ruleFileSkipped(s.file, s.reason))), "");

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
  for (const s of report.statuses) out.push(c.dim(`  ${m.engineNames[s.engine]}${sep} ${statusText(s)}`));
  if (opts.failed && opts.failOn) out.push("", c.dim(m.report.failOn(m.severity[opts.failOn].toLowerCase())));
  return `${out.join("\n")}\n`;
}

function statusText(s: EngineStatus): string {
  const m = messages().report;
  switch (s.state) {
    case "ok":
      return s.detail ? `${m.engineOk(s.count)}; ${s.detail}` : m.engineOk(s.count);
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
