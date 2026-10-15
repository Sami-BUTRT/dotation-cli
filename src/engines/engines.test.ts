import { describe, expect, it } from "vitest";
import { hasCommand } from "../core/exec.js";
import { messages } from "../i18n/index.js";
import { scan } from "../scan.js";
import { FAKE_SECRETS, fixtureRepo } from "../test/helpers.js";
import { gitleaksEngine, gitleaksSeverity, parseGitleaks, supabaseRole } from "./gitleaks.js";
import { compareVersions, cvssToSeverity, osvDbDir, osvEngine, parseOsv } from "./osv.js";
import { parseSemgrep, semgrepEngine } from "./semgrep.js";

const en = messages();

describe("Gitleaks : lecture du rapport", () => {
  // Assemblée à l'exécution : écrite d'un bloc, la protection anti-fuite de GitHub la prendrait pour une vraie clé.
  const stripeKey = ["sk", "live", "51HabcdefghijklmnopWXYZ"].join("_");
  const leak = {
    RuleID: "stripe-access-token",
    File: "/repo/src/pay.ts",
    StartLine: 3,
    Secret: stripeKey,
    Match: `key = "${stripeKey}"`,
    Line: `const key = "${stripeKey}";`,
  };
  it("le secret brut ne figure dans aucun champ", () => {
    const [f] = parseGitleaks(JSON.stringify([leak]), "/repo", en);
    expect(f).toBeDefined();
    expect(JSON.stringify(f)).not.toContain("51Habcdef");
    expect(f?.snippet).toBe('const key = "sk_live_****WXYZ";');
    expect(f?.file).toBe("src/pay.ts");
    expect(f?.severity).toBe("critical");
    expect(f?.refs).toEqual(["A07:2025", "NHI2:2025", "CWE-798"]);
  });
  it("sévérité par type de secret", () => {
    expect(gitleaksSeverity("aws-access-token")).toBe("critical");
    expect(gitleaksSeverity("generic-api-key")).toBe("high");
  });
  it("rapport vide", () => {
    expect(parseGitleaks("", "/repo", en)).toEqual([]);
  });
  const jwt = (payload: object) =>
    ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify(payload)).toString("base64url"), "c2lnbmF0dXJlLWZha2U"].join(
      ".",
    );
  it("clé Supabase anon (publique par conception) : ignorée ; service_role : critique", () => {
    const anon = jwt({ iss: "supabase", role: "anon", ref: "fake" });
    const service = jwt({ iss: "supabase", role: "service_role", ref: "fake" });
    expect(supabaseRole(anon)).toBe("anon");
    expect(supabaseRole(service)).toBe("service_role");
    expect(supabaseRole("sb_publishable_FAKE")).toBe("anon");
    expect(supabaseRole("pas.un.jwt")).toBeNull();
    expect(
      parseGitleaks(
        JSON.stringify([{ ...leak, RuleID: "jwt", Secret: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", Match: "x" }]),
        "/repo",
        en,
      ),
    ).toEqual([]);
    const out = parseGitleaks(
      JSON.stringify([
        { ...leak, RuleID: "jwt", Secret: anon, Match: anon, Line: `const k = "${anon}"` },
        { ...leak, RuleID: "jwt", Secret: service, Match: service, Line: `const k = "${service}"` },
      ]),
      "/repo",
      en,
    );
    expect(out).toHaveLength(1);
    expect(out[0]?.severity).toBe("critical");
    expect(JSON.stringify(out)).not.toContain(service);
  });
});

describe("Semgrep : lecture du rapport", () => {
  it("textes anglais de nos règles, repli sur la sévérité Semgrep", () => {
    const json = JSON.stringify({
      results: [
        {
          check_id: "engines.semgrep.sql-injection-js",
          path: "server.js",
          start: { line: 4 },
          extra: {
            severity: "ERROR",
            lines: "requires login",
            metadata: {
              dotation: {
                severity: "critical",
                refs: ["A05:2025", "CWE-89", "pas-une-ref"],
                en: { title: "Possible SQL injection", explanation: "e", fix: "f" },
              },
            },
          },
        },
        { check_id: "x.other", path: "./a.py", start: { line: 1 }, extra: { severity: "WARNING", message: "msg" } },
      ],
    });
    const [a, b] = parseSemgrep(json);
    expect(a).toMatchObject({
      id: "semgrep:sql-injection-js",
      severity: "critical",
      title: "Possible SQL injection",
      snippet: "",
      refs: ["A05:2025", "CWE-89"],
    });
    expect(b).toMatchObject({ id: "semgrep:other", severity: "medium", title: "msg", file: "a.py" });
    expect(b?.refs).toBeUndefined();
  });
});

describe("OSV : lecture du rapport", () => {
  it("un constat par paquet : toutes ses failles, la plus haute version corrigée, la pire sévérité", () => {
    const json = JSON.stringify({
      results: [
        {
          source: { path: "/repo/package-lock.json" },
          packages: [
            {
              package: { name: "lodash", version: "4.17.15", ecosystem: "npm" },
              vulnerabilities: [
                {
                  id: "GHSA-p6mc-m468-83gw",
                  summary: "Prototype pollution in lodash",
                  affected: [
                    { package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.19" }] }] },
                  ],
                },
                { id: "CVE-2020-8203" },
                {
                  id: "GHSA-35jh-r3h4-6jhm",
                  affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ fixed: "4.17.21" }] }] }],
                },
              ],
              groups: [
                { ids: ["CVE-2020-8203", "GHSA-p6mc-m468-83gw"], max_severity: "7.4" },
                { ids: ["GHSA-35jh-r3h4-6jhm"], max_severity: "9.1" },
              ],
            },
          ],
        },
      ],
    });
    const out = parseOsv(json, "/repo", en);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      id: "osv:npm/lodash",
      severity: "critical",
      file: "package-lock.json",
      title: "lodash@4.17.15: 2 known vulnerabilities",
      fix: "Update lodash to 4.17.21 or later.",
      refs: ["A03:2025", "CWE-1395"],
    });
    expect(out[0]?.explanation).toContain("GHSA-p6mc-m468-83gw");
  });
  it("comparaison de versions", () => {
    expect(compareVersions("4.17.21", "4.17.9")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0", "1.0.0")).toBe(0);
    expect(compareVersions("2.0.0-rc.1", "10.0.0")).toBeLessThan(0);
  });
  it("CVSS -> sévérité", () => {
    expect(cvssToSeverity("9.8")).toBe("critical");
    expect(cvssToSeverity("7.0")).toBe("high");
    expect(cvssToSeverity("5")).toBe("medium");
    expect(cvssToSeverity("2.1")).toBe("low");
    expect(cvssToSeverity(undefined)).toBe("medium");
  });
});

// Moteurs réels : exécutés seulement s'ils sont installés (sur le VPS de dev, ils le sont).
describe.runIf(await hasCommand("gitleaks", ["version"]))("Gitleaks réel", () => {
  it("trouve les secrets de la fixture, masqués, et ignore les .env non versionnés", async () => {
    const repo = await fixtureRepo("vulnerable-app", false);
    const r = await scan(repo, { engines: [gitleaksEngine] });
    expect(r.statuses[0]?.state).toBe("ok");
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.findings.some((f) => f.file === ".env")).toBe(false);
    const out = JSON.stringify(r);
    for (const s of FAKE_SECRETS) expect(out).not.toContain(s);
  });
});

describe.runIf(await hasCommand("semgrep", ["--version"]))("Semgrep réel (règles locales)", () => {
  it("trouve injections SQL, commandes, eval, XSS et désérialisation", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [semgrepEngine] });
    expect(r.statuses[0]).toMatchObject({ state: "ok" });
    const ids = new Set(r.findings.map((f) => f.id));
    for (const id of [
      "semgrep:sql-injection-js",
      "semgrep:sql-injection-py",
      "semgrep:command-injection-js",
      "semgrep:command-injection-py",
      "semgrep:eval-dynamic",
      "semgrep:dangerously-set-inner-html",
      "semgrep:unsafe-deserialization-py",
    ]) {
      expect(ids, id).toContain(id);
    }
    expect(r.findings.every((f) => f.snippet.length > 0)).toBe(true);
    expect(r.findings.find((f) => f.id === "semgrep:sql-injection-js")?.title).toBe("Injection SQL possible");
  });
  it("rien sur l'application propre", async () => {
    const repo = await fixtureRepo("clean-app");
    const r = await scan(repo, { engines: [semgrepEngine] });
    expect(r.findings).toEqual([]);
  });
});

const osvReady = (await hasCommand("osv-scanner", ["--version"])) && osvDbDir() !== "";
describe.runIf(osvReady)("OSV-Scanner réel (hors ligne)", () => {
  it("trouve les dépendances vulnérables du package-lock, sans réseau", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [osvEngine] });
    if (r.statuses[0]?.state === "missing") return; // base pas encore téléchargée sur cette machine
    expect(r.statuses[0]?.state).toBe("ok");
    expect(r.findings.map((f) => f.id).sort()).toEqual(["osv:npm/express", "osv:npm/jsonwebtoken", "osv:npm/lodash"]);
  });
});

// Promesse du produit : aucune donnée envoyée pendant un scan. strace trace chaque tentative de connexion réseau,
// y compris celles des moteurs externes (Semgrep contacte ses serveurs si on oublie de désactiver la vérification de version).
describe.runIf((await hasCommand("strace", ["-V"])) && process.platform === "linux")("aucune connexion réseau", () => {
  it("un scan complet (4 moteurs) n'ouvre aucune connexion hors de la machine", async () => {
    const { execFile } = await import("node:child_process");
    const { readFile, rm } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const { packagePath } = await import("../paths.js");
    const { tempDir } = await import("../test/helpers.js");
    const repo = await fixtureRepo("vulnerable-app");
    const trace = join(await tempDir(), "trace.txt");
    await new Promise<void>((resolve) => {
      execFile(
        "strace",
        [
          "-f",
          "-qq",
          "-e",
          "trace=connect",
          "-o",
          trace,
          process.execPath,
          packagePath("dist/cli.js"),
          "scan",
          repo,
          "--format",
          "json",
        ],
        { maxBuffer: 64 * 1024 * 1024 },
        () => resolve(),
      );
    });
    const lines = (await readFile(trace, "utf8")).split("\n").filter((l) => /AF_INET6?/.test(l));
    const external = lines.filter((l) => !/127\.0\.0\.|"::1"|inet_addr\("0\.0\.0\.0"\)/.test(l));
    await rm(trace, { force: true });
    expect(external).toEqual([]);
  });
});
