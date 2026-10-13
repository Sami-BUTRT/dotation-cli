import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { houseEngine } from "../engines/house.js";
import { scan } from "../scan.js";
import { fixtureRepo, tempDir } from "../test/helpers.js";
import { gitignoreCovers } from "./detectors.js";
import { BUILTIN_RULES_DIR, loadRuleDir, loadRules, RuleError } from "./loader.js";

describe("règles livrées", () => {
  it("se chargent, ont des identifiants uniques et des textes FR et EN complets", async () => {
    const rules = await loadRuleDir(BUILTIN_RULES_DIR);
    expect(rules.length).toBeGreaterThanOrEqual(15);
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
    for (const r of rules) {
      expect(r.text.fr, `${r.id} fr`).toBeDefined();
      expect(r.text.en, `${r.id} en`).toBeDefined();
    }
  });

  it("couvrent les cas du cahier des charges", async () => {
    const ids = (await loadRuleDir(BUILTIN_RULES_DIR)).map((r) => r.id);
    for (const id of [
      "DOT-CFG-001", // .env versionné
      "DOT-CFG-002", // clés .pem / id_rsa versionnées
      "DOT-CFG-003", // .env absent du .gitignore
      "DOT-ACC-001", // CORS Express / Fastify
      "DOT-ACC-002", // CORS Next.js (en-têtes)
      "DOT-ACC-003", // CORS FastAPI / Flask
      "DOT-SEC-004", // NEXT_PUBLIC_ / VITE_ secret
      "DOT-SEC-003", // mot de passe en clair
      "DOT-ACC-004", // Supabase sans RLS
      "DOT-ACC-005", // Firebase if true
    ]) {
      expect(ids).toContain(id);
    }
  });
});

describe("règles du projet (.dotation/rules)", () => {
  it("s'ajoutent aux règles livrées et peuvent en remplacer une", async () => {
    const d = await tempDir();
    await mkdir(join(d, ".dotation", "rules"), { recursive: true });
    await writeFile(
      join(d, ".dotation", "rules", "maison.yaml"),
      `- id: ACME-TODO-001
  severity: low
  category: code
  detector: { type: regex, files: ["**/*.ts"], pattern: "TODO SECURITE" }
  text: { fr: { title: À faire, explanation: Note de sécurité oubliée., fix: Traite-la. } }
- id: DOT-ACC-001
  severity: low
  category: access
  detector: { type: regex, files: ["**/*.none"], pattern: "x" }
  text: { en: { title: off, explanation: off, fix: off } }
`,
    );
    await writeFile(join(d, "a.ts"), "// TODO SECURITE : vérifier les droits\napp.use(cors());\n");
    const report = await scan(d, { engines: [houseEngine], lang: "fr" });
    expect(report.findings.map((f) => f.id)).toEqual(["ACME-TODO-001"]);
    expect(report.findings[0]?.title).toBe("À faire");
  });

  it("une règle invalide est refusée avec un message clair", async () => {
    const d = await tempDir();
    await writeFile(join(d, "bad.yaml"), "- id: pas-bon\n  severity: énorme\n");
    await expect(loadRuleDir(d)).rejects.toThrow(RuleError);
    await writeFile(
      join(d, "bad.yaml"),
      `- id: ACME-X-001
  severity: low
  category: code
  detector: { type: regex, files: ["*"], pattern: "(" }
  text: { en: { title: t, explanation: e, fix: f } }
`,
    );
    await expect(loadRuleDir(d)).rejects.toThrow(/invalid pattern/);
  });

  it("un dossier absent ne gêne pas", async () => {
    expect(await loadRules(["/dossier/inexistant"])).not.toHaveLength(0);
  });
});

describe("règles maison sur la fixture vulnérable", () => {
  it("chaque règle livrée se déclenche (dépôt git, .env et clé versionnés)", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const report = await scan(repo, { engines: [houseEngine], lang: "en" });
    const ids = new Set(report.findings.map((f) => f.id));
    const all = (await loadRuleDir(BUILTIN_RULES_DIR)).map((r) => r.id);
    expect([...all].filter((id) => !ids.has(id))).toEqual([]);
    expect(report.findings.every((f) => f.engine === "house")).toBe(true);
  });

  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const report = await scan(repo, { engines: [houseEngine], lang: "fr" });
    const at = (id: string) => report.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-ACC-004")).toEqual(["supabase/migrations/0001_init.sql:8"]); // orders, pas profiles ni private.audit
    expect(at("DOT-ACC-005")).toEqual(["firestore.rules:6"]);
    expect(at("DOT-CFG-001")).toEqual([".env:0"]);
    expect(at("DOT-CFG-002")).toEqual(["keys/server.pem:0"]);
    expect(at("DOT-SEC-005")).toEqual(["app/admin/page.tsx:5"]);
    expect(at("DOT-SEC-001")).toHaveLength(4); // AWS, GitHub, OpenAI (config.ts) + Stripe (.env versionné)
  });

  it("une fixture non commitée : pas de règle « versionné », .env non suivi ignoré par les règles de secrets", async () => {
    const repo = await fixtureRepo("vulnerable-app", false);
    const report = await scan(repo, { engines: [houseEngine] });
    const ids = report.findings.map((f) => f.id);
    expect(ids).not.toContain("DOT-CFG-001");
    expect(report.findings.filter((f) => f.file === ".env").map((f) => f.id)).toEqual(["DOT-SEC-004"]);
  });
});

describe("détails des détecteurs", () => {
  it("lecture simplifiée du .gitignore (hors git)", () => {
    expect(gitignoreCovers("node_modules\n.env\n", ".env")).toBe(true);
    expect(gitignoreCovers("/.env\n", ".env")).toBe(true);
    expect(gitignoreCovers(".env*\n", ".env")).toBe(true);
    expect(gitignoreCovers("node_modules\n", ".env")).toBe(false);
    expect(gitignoreCovers(".env\n!.env\n", ".env")).toBe(false);
  });

  it("valeurs d'exemple et variables d'environnement ne sont pas des secrets", async () => {
    const d = await tempDir();
    await writeFile(
      join(d, "a.ts"),
      [
        "const password = process.env.DB_PASSWORD;",
        'const cfg = { password: "changeme" };',
        'const field = { type: "password", label: "Password" };',
        'const aws = "AKIAIOSFODNN7EXAMPLE";',
        'const pwd = "<your-password>";',
      ].join("\n"),
    );
    const report = await scan(d, { engines: [houseEngine] });
    expect(report.findings).toEqual([]);
  });

  it("Supabase : RLS activé dans une autre migration, schéma explicite et guillemets", async () => {
    const d = await tempDir();
    await mkdir(join(d, "supabase", "migrations"), { recursive: true });
    await writeFile(
      join(d, "supabase/migrations/1.sql"),
      'create table "public"."notes" (id int);\ncreate table todos (id int);\n',
    );
    await writeFile(
      join(d, "supabase/migrations/2.sql"),
      "alter table public.notes enable row level security;\n-- alter table todos enable row level security;\n",
    );
    const report = await scan(d, { engines: [houseEngine] });
    expect(report.findings.map((f) => `${f.id} ${f.file}:${f.line}`)).toEqual([
      "DOT-ACC-004 supabase/migrations/1.sql:2",
    ]);
  });

  it("une ligne énorme (fichier minifié) est ignorée", async () => {
    const d = await tempDir();
    await writeFile(join(d, "bundle.js"), `var a=1;${"x".repeat(5000)}app.use(cors());`);
    expect((await scan(d, { engines: [houseEngine] })).findings).toEqual([]);
  });
});

describe("faux positifs trouvés sur de vrais projets", () => {
  it("autoComplete et .env.local.example ne sont pas des problèmes", async () => {
    const d = await fixtureRepo("clean-app", false);
    await writeFile(
      join(d, "login.tsx"),
      'const a = <input autoComplete={mode === "signin" ? "current-password" : "new-password"} />;\n',
    );
    await writeFile(join(d, ".env.local.example"), "NEXT_PUBLIC_SUPABASE_URL=\nSUPABASE_SERVICE_ROLE_KEY=\n");
    const { git } = await import("../test/helpers.js");
    git(d, "add", "-A");
    git(d, "commit", "-q", "-m", "x");
    expect((await scan(d, { engines: [houseEngine] })).findings).toEqual([]);
  });

  it("un .env versionné qui ne contient que des variables publiques : sévérité faible", async () => {
    const d = await fixtureRepo("clean-app", false);
    await writeFile(join(d, ".gitignore"), "node_modules\n");
    await writeFile(
      join(d, ".env"),
      "VITE_SUPABASE_URL=https://fake.supabase.co\nVITE_SUPABASE_PUBLISHABLE_KEY=fake\n",
    );
    const { git } = await import("../test/helpers.js");
    git(d, "add", "-A");
    git(d, "commit", "-q", "-m", "x");
    const f = (await scan(d, { engines: [houseEngine] })).findings.find((x) => x.id === "DOT-CFG-001");
    expect(f?.severity).toBe("low");
  });

  it("code caché après une longue suite d'espaces (faux dépôts piégés), même sur une ligne de 13 000 caractères", async () => {
    const d = await tempDir();
    const payload = `global.i='x';${"var _0x1=1;".repeat(1200)}`;
    await writeFile(
      join(d, "postcss.config.mjs"),
      `const config = {};\nexport default config;${" ".repeat(507)}${payload}\n`,
    );
    await writeFile(join(d, "ok.ts"), `const s = "${" ".repeat(10)}";\n`);
    const r = await scan(d, { engines: [houseEngine], lang: "fr" });
    expect(r.findings.map((f) => `${f.id} ${f.file}:${f.line}`)).toEqual(["DOT-SEC-007 postcss.config.mjs:2"]);
    expect(r.findings[0]?.snippet).toContain("507 espaces");
  });

  it("commentaire dotation-ignore : toutes les règles, ou seulement celles citées", async () => {
    const d = await tempDir();
    await writeFile(
      join(d, "a.js"),
      [
        "const x = { rejectUnauthorized: false }; // dotation-ignore",
        "// dotation-ignore: DOT-CODE-001",
        "const y = { rejectUnauthorized: false };",
        "// dotation-ignore: DOT-ACC-001",
        "const z = { rejectUnauthorized: false };",
      ].join("\n"),
    );
    const r = await scan(d, { engines: [houseEngine] });
    expect(r.findings.map((f) => `${f.id}:${f.line}`)).toEqual(["DOT-CODE-001:5"]);
  });
});
