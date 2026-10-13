import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { houseEngine } from "./engines/house.js";
import { renderJson } from "./output/json.js";
import { renderPretty } from "./output/pretty.js";
import { renderSarif } from "./output/sarif.js";
import { scan } from "./scan.js";
import { FAKE_SECRETS, fixtureRepo, git, pathWithoutEngines, tempDir } from "./test/helpers.js";

// Critères de réussite du MVP (cahier des charges).
describe("critères de réussite", () => {
  it("la fixture vulnérable remonte au moins 10 problèmes différents, expliqués", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { lang: "fr" });
    const distinct = new Set(r.findings.map((f) => f.id));
    expect(distinct.size).toBeGreaterThanOrEqual(10);
    for (const f of r.findings) {
      expect(f.title.length).toBeGreaterThan(0);
      expect(f.explanation.length).toBeGreaterThan(0);
    }
    expect(r.score).toBe(0);
  });

  it("un projet propre obtient 100", async () => {
    const repo = await fixtureRepo("clean-app");
    const r = await scan(repo);
    expect(r.findings).toEqual([]);
    expect(r.score).toBe(100);
  });

  describe("sans Gitleaks, Semgrep ni OSV-Scanner", () => {
    let saved: string | undefined;
    beforeEach(() => {
      saved = process.env.PATH;
      process.env.PATH = pathWithoutEngines();
    });
    afterEach(() => {
      process.env.PATH = saved;
    });
    it("le scan fonctionne avec les règles maison seules et dit comment installer les moteurs", async () => {
      const repo = await fixtureRepo("vulnerable-app");
      const r = await scan(repo, { lang: "fr" });
      expect(r.statuses.map((s) => `${s.engine}:${s.state}`)).toEqual([
        "house:ok",
        "gitleaks:missing",
        "semgrep:missing",
        "osv:missing",
      ]);
      expect(new Set(r.findings.map((f) => f.id)).size).toBeGreaterThanOrEqual(10);
      const pretty = renderPretty(r, { all: false, color: false });
      expect(pretty).toContain("brew install gitleaks");
      expect(pretty).toContain("pipx install semgrep");
    });
  });
});

describe("aucun secret dans les sorties", () => {
  it("pretty, json et sarif ne contiennent aucune valeur complète de secret", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo);
    for (const out of [renderPretty(r, { all: true, color: false }), renderJson(r), renderSarif(r)]) {
      for (const s of FAKE_SECRETS) expect(out).not.toContain(s);
    }
  });
});

describe("périmètre", () => {
  it("--staged : seulement les fichiers indexés, lus depuis l'index", async () => {
    const d = await tempDir();
    git(d, "init", "-q");
    await writeFile(join(d, "staged.ts"), 'const k = "AKIAFAKEDOTATION0001";\n');
    await writeFile(join(d, "unstaged.ts"), 'const k = "AKIAFAKEDOTATION0002";\n');
    git(d, "add", "staged.ts");
    // Modification après l'indexation : c'est la version indexée qui compte.
    await writeFile(join(d, "staged.ts"), "const k = process.env.KEY;\n");
    const r = await scan(d, { staged: true, engines: [houseEngine] });
    expect(r.findings.map((f) => `${f.id} ${f.file}`)).toEqual(["DOT-SEC-001 staged.ts"]);
  });

  it("--staged hors dépôt git : erreur claire", async () => {
    const d = await tempDir();
    await expect(scan(d, { staged: true })).rejects.toThrow("not-a-git-repo");
  });

  it("un fichier seul", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(join(repo, "server.js"), { engines: [houseEngine] });
    expect(r.fileCount).toBe(1);
    expect(new Set(r.findings.map((f) => f.file))).toEqual(new Set(["server.js"]));
  });

  it("--scope dir : sans descendre dans les sous-dossiers", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { scope: "dir", engines: [houseEngine] });
    expect(r.findings.every((f) => !f.file.includes("/") || f.line === 0)).toBe(true);
  });

  it("node_modules, dist et .next ne sont jamais analysés", async () => {
    const d = await tempDir();
    for (const dir of ["node_modules/pkg", "dist", ".next/server"]) {
      await import("node:fs/promises").then((fs) => fs.mkdir(join(d, dir), { recursive: true }));
      await writeFile(join(d, dir, "x.js"), 'app.use(cors()); const k = "AKIAFAKEDOTATION0003";\n');
    }
    expect((await scan(d, { engines: [houseEngine] })).findings).toEqual([]);
  });
});

describe(".dotation.yml", () => {
  it("désactive une règle, exclut un dossier", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    await writeFile(join(repo, ".dotation.yml"), 'disable: [DOT-ACC-005]\nexclude: ["api/**"]\n');
    const r = await scan(repo, { engines: [houseEngine] });
    const ids = r.findings.map((f) => f.id);
    expect(ids).not.toContain("DOT-ACC-005");
    expect(r.findings.some((f) => f.file.startsWith("api/"))).toBe(false);
  });
  it("une clé inconnue est refusée", async () => {
    const d = await tempDir();
    await writeFile(join(d, ".dotation.yml"), "failon: high\n");
    await expect(scan(d)).rejects.toThrow(/\.dotation\.yml/);
  });
});

describe("langues", () => {
  it("fr, en ; es et zh avec repli anglais pour les textes non traduits", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const fr = await scan(repo, { engines: [houseEngine], lang: "fr" });
    const zh = await scan(repo, { engines: [houseEngine], lang: "zh" });
    expect(renderPretty(fr, { all: false, color: false })).toContain("Score d'hygiène");
    const z = renderPretty(zh, { all: false, color: false });
    expect(z).toContain("卫生评分");
    expect(zh.findings[0]?.title).toMatch(/[A-Za-z]/); // texte de règle : repli anglais
  });
});
