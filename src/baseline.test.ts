import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildProgram } from "./cli.js";
import { fingerprint, MAX_BASELINE_BYTES } from "./core/baseline.js";
import { houseEngine } from "./engines/house.js";
import { renderJson } from "./output/json.js";
import { renderPretty } from "./output/pretty.js";
import { toSarif } from "./output/sarif.js";
import { scan } from "./scan.js";
import { tempDir } from "./test/helpers.js";

const FAKE = ["sk", "live", "FAKEbaselineTEST0000000000"].join("_");
const opts = { engines: [houseEngine] } as const;
const trap = (tail = "") => `export default {};${" ".repeat(300)}global.i='x';${tail}\n`;

async function project(): Promise<string> {
  const d = await tempDir();
  await writeFile(
    join(d, "app.js"),
    `const a = 1;\nconst key = "${FAKE}";\nfetch(url, { rejectUnauthorized: false });\n`,
  );
  return d;
}

async function freeze(d: string): Promise<number> {
  const out: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((s: string) => (out.push(String(s)), true)) as typeof process.stdout.write;
  try {
    await buildProgram().parseAsync(["node", "dotation", "baseline", d]);
  } finally {
    process.stdout.write = orig;
  }
  return Number(/(\d+) finding/.exec(out.join(""))?.[1] ?? -1);
}

describe("baseline", () => {
  it("crée la baseline sans aucune valeur de secret", async () => {
    const d = await project();
    const before = await scan(d, { ...opts, baseline: false });
    expect(before.findings.length).toBeGreaterThan(0);
    expect(await freeze(d)).toBeGreaterThan(0);
    const raw = await readFile(join(d, ".dotation", "baseline.json"), "utf8");
    expect(raw).not.toContain(FAKE);
    expect(raw).not.toContain("sk_live");
    const j = JSON.parse(raw);
    expect(j.version).toBe(1);
    expect(j.entries[0]).toEqual({
      ruleId: expect.any(String),
      file: "app.js",
      fingerprint: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
  });

  it("masque les constats gelés, même déplacés, et remonte les nouveaux", async () => {
    const d = await project();
    await freeze(d);
    const same = await scan(d, opts);
    expect(same.findings).toEqual([]);
    expect(same.suppressed?.baseline).toBeGreaterThan(0);
    expect(same.score).toBe(100);
    // Lignes vides ajoutées au-dessus : même empreinte.
    await writeFile(
      join(d, "app.js"),
      `\n\n\nconst a = 1;\nconst key = "${FAKE}";\n  fetch(url,  { rejectUnauthorized: false });\n`,
    );
    expect((await scan(d, opts)).findings).toEqual([]);
    // Nouveau constat : remonté.
    await writeFile(join(d, "b.js"), `fetch(u, { rejectUnauthorized: false });\n`);
    const next = await scan(d, opts);
    expect(next.findings.map((f) => f.file)).toEqual(["b.js"]);
    const out = renderPretty(next, { all: true, color: false });
    expect(out).toContain("already known finding");
    expect(out).toContain("--no-baseline");
    expect(JSON.parse(renderJson(next)).suppressed.baseline).toBeGreaterThan(0);
  });

  it("--no-baseline montre tout ; --baseline <file> utilise un autre fichier", async () => {
    const d = await project();
    await freeze(d);
    const all = await scan(d, { ...opts, baseline: false });
    expect(all.findings.length).toBeGreaterThan(0);
    expect(all.suppressed?.baseline).toBeUndefined();
    const other = await scan(d, { ...opts, baseline: join(d, ".dotation", "baseline.json") });
    expect(other.findings).toEqual([]);
    const missing = await scan(d, { ...opts, baseline: join(d, "nope.json") });
    expect(missing.findings.length).toBeGreaterThan(0);
  });

  it("DOT-SEC-007 n'est jamais masquée par une baseline", async () => {
    const d = await tempDir();
    await writeFile(join(d, "postcss.config.mjs"), trap());
    await freeze(d);
    const j = JSON.parse(await readFile(join(d, ".dotation", "baseline.json"), "utf8"));
    expect(j.entries).toEqual([]);
    const r = await scan(d, opts);
    expect(r.findings.map((f) => f.id)).toEqual(["DOT-SEC-007"]);
    expect(r.suppressed?.baseline ?? 0).toBe(0);
  });

  it("baseline mal formée, trop grosse ou trop longue : ignorée avec un avis, sans plantage", async () => {
    const d = await project();
    const file = join(d, ".dotation", "baseline.json");
    await mkdir(join(d, ".dotation"), { recursive: true });
    const cases: [string, string][] = [
      ["{ pas du json", "malformed"],
      [JSON.stringify({ version: 2, entries: [] }), "malformed"],
      [`{"version":1,"entries":[],"pad":"${"x".repeat(MAX_BASELINE_BYTES)}"}`, "too-large"],
    ];
    for (const [content, reason] of cases) {
      await writeFile(file, content);
      const r = await scan(d, opts);
      expect(r.suppressed?.baselineInvalid).toBe(reason);
      expect(r.findings.length).toBeGreaterThan(0);
      expect(renderPretty(r, { all: true, color: false })).toContain("ignored");
    }
    const fp = "a".repeat(64);
    await writeFile(
      file,
      JSON.stringify({
        version: 1,
        entries: Array.from({ length: 40_001 }, () => ({ ruleId: "x", file: "y", fingerprint: fp })),
      }),
    );
    expect((await scan(d, opts)).suppressed?.baselineInvalid).toBe("too-many-entries");
  });

  it("SARIF : baselineState new / unchanged", async () => {
    const d = await project();
    await freeze(d);
    await writeFile(join(d, "b.js"), `fetch(u, { rejectUnauthorized: false });\n`);
    const sarif = toSarif(await scan(d, opts));
    const states = new Map(
      sarif.runs[0]?.results.map((r) => [r.locations[0]?.physicalLocation.artifactLocation.uri, r.baselineState]),
    );
    expect(states.get("b.js")).toBe("new");
    expect(states.get("app.js")).toBe("unchanged");
    const none = toSarif(await scan(d, { ...opts, baseline: false }));
    expect(none.runs[0]?.results.every((r) => !("baselineState" in r))).toBe(true);
  });

  it("empreinte d'un secret : calculée sur l'extrait masqué, jamais sur la ligne brute", async () => {
    const d = await project();
    const r = await scan(d, { ...opts, baseline: false, collectEntries: true });
    const f = r.findings.find((x) => x.category === "secret");
    expect(f).toBeDefined();
    if (!f) return;
    expect(f.snippet).not.toContain(FAKE);
    const entry = r.entries?.find((e) => e.ruleId === f.id && e.file === f.file);
    expect(entry?.fingerprint).toBe(fingerprint(f.id, f.file, f.snippet, true));
    expect(entry?.fingerprint).not.toBe(fingerprint(f.id, f.file, `const key = "${FAKE}";`));
  });

  it("suppressed.ignored ne compte que dotation-ignore, suppressed.baseline que la baseline", async () => {
    const d = await project();
    await freeze(d);
    const frozen = (await scan(d, opts)).suppressed?.baseline ?? 0;
    expect(frozen).toBeGreaterThan(0);
    await writeFile(join(d, "c.js"), `fetch(u, { rejectUnauthorized: false }); // dotation-ignore\n`);
    const r = await scan(d, opts);
    expect(r.suppressed?.ignored).toBe(1);
    expect(r.suppressed?.baseline).toBe(frozen);
  });

  async function freezeRaw(d: string): Promise<{ code: number; err: string }> {
    const err: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    const origOut = process.stdout.write.bind(process.stdout);
    process.stderr.write = ((s: string) => (err.push(String(s)), true)) as typeof process.stderr.write;
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      await buildProgram().parseAsync(["node", "dotation", "baseline", d]);
    } finally {
      process.stderr.write = orig;
      process.stdout.write = origOut;
    }
    const code = Number(process.exitCode ?? 0);
    process.exitCode = 0;
    return { code, err: err.join("") };
  }

  it("baseline.json lien symbolique : écriture refusée, cible intacte", async () => {
    const d = await project();
    const target = join(await tempDir(), "victim");
    await writeFile(target, "ORIGINAL\n");
    await mkdir(join(d, ".dotation"), { recursive: true });
    await symlink(target, join(d, ".dotation", "baseline.json"));
    const r = await freezeRaw(d);
    expect(r.code).toBe(2);
    expect(r.err).toContain("symbolic link");
    expect(await readFile(target, "utf8")).toBe("ORIGINAL\n");
  });

  it(".dotation lien symbolique : écriture refusée, cible intacte", async () => {
    const d = await project();
    const outside = await tempDir();
    await symlink(outside, join(d, ".dotation"));
    const r = await freezeRaw(d);
    expect(r.code).toBe(2);
    expect(r.err).toContain("symbolic link");
    await expect(readFile(join(outside, "baseline.json"), "utf8")).rejects.toThrow();
  });

  it(".dotation lien symbolique vers l'extérieur : baseline ignorée", async () => {
    const d = await project();
    const outside = await tempDir();
    await writeFile(join(outside, "baseline.json"), '{"version":1,"entries":[]}');
    await symlink(outside, join(d, ".dotation"));
    const { loadBaseline } = await import("./core/baseline.js");
    expect(await loadBaseline(join(d, ".dotation", "baseline.json"), d)).toEqual({
      state: "invalid",
      reason: "unreadable",
    });
  });

  it("règle projet avec secretGroup (catégorie config) : baseline sans secret brut, empreinte masquée", async () => {
    const d = await tempDir();
    await mkdir(join(d, ".dotation", "rules"), { recursive: true });
    await writeFile(
      join(d, ".dotation", "rules", "acme.yaml"),
      `- id: ACME-CFG-001
  severity: low
  category: config
  detector: { type: regex, files: ["**/*.ts"], pattern: "token=(?<tok>[A-Za-z0-9]{16,})", secretGroup: tok }
  text: { en: { title: t, explanation: e, fix: f } }
`,
    );
    const raw = "FAKEcfgSECRET0123456789";
    await writeFile(join(d, "a.ts"), `const c = "token=${raw}";\n`);
    const r = await scan(d, { ...opts, baseline: false, collectEntries: true });
    const f = r.findings.find((x) => x.id === "ACME-CFG-001");
    expect(f).toBeDefined();
    await freeze(d);
    const txt = await readFile(join(d, ".dotation", "baseline.json"), "utf8");
    expect(txt).not.toContain(raw);
    expect(txt).toContain(fingerprint("ACME-CFG-001", "a.ts", f?.snippet ?? "", true));
  });

  it("baselineFile n'expose jamais de chemin absolu", async () => {
    const d = await project();
    await freeze(d);
    const other = await tempDir();
    await writeFile(join(other, "b.json"), await readFile(join(d, ".dotation", "baseline.json"), "utf8"));
    const r = await scan(d, { ...opts, baseline: join(other, "b.json") });
    expect(r.suppressed?.baseline).toBeGreaterThan(0);
    expect(r.suppressed?.baselineFile).toBe("b.json");
    expect(renderJson(r)).not.toContain(other);
  });
});
