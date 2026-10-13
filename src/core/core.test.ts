import { describe, expect, it } from "vitest";
import { dedupe } from "./dedupe.js";
import { run } from "./exec.js";
import { atLeast, compareFindings, type Finding } from "./finding.js";
import { matchAny, matchGlob } from "./glob.js";
import { maskSecret, redactLine } from "./mask.js";
import { hygieneScore } from "./score.js";

const f = (over: Partial<Finding>): Finding => ({
  id: "X",
  engine: "house",
  severity: "high",
  category: "secret",
  title: "t",
  explanation: "e",
  fix: "x",
  file: "a.ts",
  line: 1,
  snippet: "",
  ...over,
});

describe("masquage des secrets", () => {
  it("garde le préfixe connu et 4 caractères de fin, jamais la valeur", () => {
    expect(maskSecret(["sk", "live", "51HabcdefghijklmnopWXYZ"].join("_"))).toBe("sk_live_****WXYZ");
    expect(maskSecret("ghp_abcdefghijklmnopqrstuvwxyz0123456789")).toBe("ghp_****6789");
    expect(maskSecret("AKIAIOSFODNN7ABCDEFG")).toBe("****DEFG");
  });
  it("ne montre que la fin d'un secret générique, et rien d'un secret court", () => {
    expect(maskSecret("fake-fixture-jwt-secret")).toBe("****cret");
    expect(maskSecret("hunter2pass")).toBe("****");
  });
  it("ne révèle jamais plus qu'une petite partie", () => {
    for (const s of [
      ["sk", "live", "AAAAAAAAAAAAAAAAAAAAAAAA"].join("_"),
      `xox${"b"}-1234567890-abcdefghijklmnop`,
      "a".repeat(64),
    ]) {
      const m = maskSecret(s);
      expect(m).not.toContain(s);
      expect(m.replace("****", "").length).toBeLessThanOrEqual(s.length / 3 + 4);
    }
  });
  it("masque toutes les occurrences dans une ligne et tronque", () => {
    const line = `const a = "${["sk", "live", "51HabcdefghijklmnopWXYZ"].join("_")}"; const b = "${["sk", "live", "51HabcdefghijklmnopWXYZ"].join("_")}"; ${"x".repeat(300)}`;
    const out = redactLine(line, [["sk", "live", "51HabcdefghijklmnopWXYZ"].join("_")]);
    expect(out).not.toContain("51Habcdef");
    expect(out.length).toBeLessThanOrEqual(160);
  });
});

describe("globs", () => {
  it.each([
    ["src/app/page.tsx", "**/*.{ts,tsx}", true],
    ["page.tsx", "**/*.tsx", true],
    ["a/node_modules/x/index.js", "**/node_modules/**", true],
    [".env.local", ".env.*", true],
    ["config/.env", ".env", true],
    ["keys/server.pem", "*.pem", true],
    ["src/app.ts", "**/*.py", false],
    ["supabase/migrations/1.sql", "supabase/**/*.sql", true],
    ["other/1.sql", "supabase/**/*.sql", false],
  ])("%s ~ %s = %s", (path, glob, want) => {
    expect(matchGlob(path, glob)).toBe(want);
  });
  it("matchAny", () => {
    expect(matchAny("dist/x.js", ["**/dist/**"])).toBe(true);
  });
});

describe("score et sévérité", () => {
  it("part de 100, retire des points, ne descend pas sous 0", () => {
    expect(hygieneScore([])).toBe(100);
    expect(hygieneScore([f({ severity: "critical" }), f({ severity: "low" })])).toBe(74);
    expect(hygieneScore(Array.from({ length: 10 }, () => f({ severity: "critical" })))).toBe(0);
  });
  it("les dépendances vulnérables comptent au plus pour 25 points", () => {
    const deps = Array.from({ length: 40 }, (_, i) => f({ category: "dependency", severity: "high", id: `osv:${i}` }));
    expect(hygieneScore(deps)).toBe(75);
    expect(hygieneScore([...deps, f({ severity: "medium" })])).toBe(71);
  });
  it("seuils", () => {
    expect(atLeast("critical", "high")).toBe(true);
    expect(atLeast("medium", "high")).toBe(false);
  });
  it("tri : plus grave d'abord", () => {
    const sorted = [f({ severity: "low" }), f({ severity: "critical" }), f({ severity: "medium" })].sort(
      compareFindings,
    );
    expect(sorted.map((x) => x.severity)).toEqual(["critical", "medium", "low"]);
  });
});

describe("dédoublonnage", () => {
  it("un secret vu par deux moteurs n'apparaît qu'une fois, le plus grave gagne", () => {
    const out = dedupe([
      f({ engine: "gitleaks", severity: "high", id: "gitleaks:x" }),
      f({ engine: "house", severity: "critical", id: "DOT-SEC-001" }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe("DOT-SEC-001");
  });
  it("à sévérité égale, garde la règle maison (textes plus pédagogiques)", () => {
    const out = dedupe([f({ engine: "gitleaks", id: "g" }), f({ engine: "house", id: "h" })]);
    expect(out[0]?.id).toBe("h");
  });
  it("garde des problèmes différents sur la même ligne", () => {
    expect(dedupe([f({ category: "secret" }), f({ category: "access" })])).toHaveLength(2);
  });
  it("dépendances : une ligne par vulnérabilité", () => {
    const dep = (id: string) => f({ category: "dependency", engine: "osv", id, file: "package-lock.json", line: 0 });
    expect(dedupe([dep("osv:A"), dep("osv:B"), dep("osv:A")])).toHaveLength(2);
  });
});

describe("sous-processus", () => {
  it("arrête un programme trop long", async () => {
    const r = await run("sleep", ["5"], { timeoutMs: 200 });
    expect(r.timedOut).toBe(true);
  });
  it("ne passe jamais par un shell", async () => {
    const r = await run("echo", ["$(whoami); rm -rf /"]);
    expect(r.stdout.trim()).toBe("$(whoami); rm -rf /");
  });
  it("programme absent : code -1, pas d'exception", async () => {
    const r = await run("dotation-programme-inexistant", []);
    expect(r.code).toBe(-1);
  });
});
