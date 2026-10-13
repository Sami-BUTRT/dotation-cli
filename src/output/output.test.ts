import { describe, expect, it } from "vitest";
import type { Finding, Severity } from "../core/finding.js";
import type { ScanReport } from "../scan.js";
import { renderJson } from "./json.js";
import { DEFAULT_LIMIT, renderPretty } from "./pretty.js";
import { toSarif } from "./sarif.js";

const finding = (i: number, severity: Severity): Finding => ({
  id: `DOT-T-${String(i).padStart(3, "0")}`,
  engine: "house",
  severity,
  category: "code",
  title: `Problème ${i}`,
  explanation: "Pourquoi.",
  fix: "Comment.",
  file: "src/a.ts",
  line: i,
  snippet: `ligne ${i}`,
});

const report = (findings: Finding[]): ScanReport => ({
  root: "/p",
  target: "/p",
  lang: "fr",
  fileCount: 3,
  findings,
  statuses: [{ engine: "house", state: "ok", count: findings.length }],
  score: 50,
});

describe("sortie pretty", () => {
  it("10 constats maximum par défaut, --all pour tout voir", () => {
    const many = Array.from({ length: 14 }, (_, i) => finding(i + 1, "medium"));
    const short = renderPretty(report(many), { all: false, color: false });
    expect(short).toContain(`Problème ${DEFAULT_LIMIT}`);
    expect(short).not.toContain("Problème 11");
    expect(short).toContain("4 autres");
    expect(renderPretty(report(many), { all: true, color: false })).toContain("Problème 14");
  });
  it("groupé par sévérité, du plus grave au moins grave, avec le résumé", () => {
    const out = renderPretty(report([finding(1, "critical"), finding(2, "low")]), { all: true, color: false });
    expect(out.indexOf("CRITIQUE")).toBeLessThan(out.indexOf("FAIBLE"));
    expect(out).toContain("Pourquoi :");
    expect(out).toContain("Comment corriger :");
    expect(out).toContain("Score d'hygiène : 50/100");
  });
  it("projet propre : message positif", () => {
    expect(renderPretty({ ...report([]), score: 100 }, { all: false, color: false })).toContain("Rien à signaler");
  });
  it("sans couleurs : aucun code ANSI", () => {
    expect(renderPretty(report([finding(1, "high")]), { all: false, color: false })).not.toMatch(/\[\d+m/);
  });
});

describe("sortie JSON", () => {
  it("tous les constats, compteurs et moteurs", () => {
    const j = JSON.parse(renderJson(report([finding(1, "high"), finding(2, "high")]))) as Record<string, unknown>;
    expect(j).toMatchObject({ version: 1, score: 50, counts: { high: 2 } });
    expect((j.findings as unknown[]).length).toBe(2);
  });
});

describe("sortie SARIF", () => {
  it("SARIF 2.1.0 valide pour GitHub Code Scanning", () => {
    const s = toSarif(report([finding(1, "critical"), finding(2, "medium"), { ...finding(3, "low"), line: 0 }]));
    expect(s.version).toBe("2.1.0");
    const run = s.runs[0];
    expect(run?.tool.driver.name).toBe("dotation");
    expect(run?.tool.driver.rules).toHaveLength(3);
    expect(run?.results.map((r) => r.level)).toEqual(["error", "warning", "note"]);
    expect(run?.tool.driver.rules[0]?.properties["security-severity"]).toBe("9.5");
    const loc = run?.results[0]?.locations[0]?.physicalLocation;
    expect(loc).toMatchObject({ artifactLocation: { uri: "src/a.ts" }, region: { startLine: 1 } });
    // Ligne 0 (fichier entier) : pas de région, GitHub refuse startLine 0.
    expect(run?.results[2]?.locations[0]?.physicalLocation).not.toHaveProperty("region");
    for (const r of run?.results ?? []) expect(r.ruleIndex).toBeGreaterThanOrEqual(0);
  });
});
