import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { houseEngine } from "../engines/house.js";
import { renderJson } from "../output/json.js";
import { renderPretty } from "../output/pretty.js";
import { toSarif } from "../output/sarif.js";
import { scan } from "../scan.js";
import { fixtureRepo, tempDir } from "../test/helpers.js";
import { gitignoreCovers } from "./detectors.js";
import { BUILTIN_RULES_DIR, loadRuleDir, loadRules, RuleError } from "./loader.js";

describe("règles livrées", () => {
  it("se chargent, ont des identifiants uniques et des textes EN complets", async () => {
    const rules = await loadRuleDir(BUILTIN_RULES_DIR);
    expect(rules.length).toBeGreaterThanOrEqual(15);
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
    for (const r of rules) {
      for (const k of ["title", "explanation", "fix"] as const) {
        expect(r.text.en[k]?.length, `${r.id} en.${k}`).toBeGreaterThan(0);
      }
      expect(JSON.stringify(r.text), `${r.id} no fr block`).not.toContain('"fr"');
      // Au moins une catégorie OWASP et une CWE précise.
      expect(
        r.refs.some((x) => !x.startsWith("CWE-")),
        `${r.id} OWASP`,
      ).toBe(true);
      expect(
        r.refs.some((x) => x.startsWith("CWE-")),
        `${r.id} CWE`,
      ).toBe(true);
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
  text: { fr: { title: A faire, explanation: Note oubliee., fix: Traite-la. }, en: { title: To do, explanation: Forgotten security note., fix: Handle it. } }
- id: DOT-ACC-001
  severity: low
  category: access
  detector: { type: regex, files: ["**/*.none"], pattern: "x" }
  text: { en: { title: off, explanation: off, fix: off } }
`,
    );
    await writeFile(join(d, "a.ts"), "// TODO SECURITE : vérifier les droits\napp.use(cors());\n");
    const report = await scan(d, { engines: [houseEngine] });
    expect(report.findings.map((f) => f.id)).toEqual(["ACME-TODO-001"]);
    expect(report.findings[0]?.title).toBe("To do");
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

  it("une règle de projet avec seulement fr est active, texte fr affiché tel quel", async () => {
    const d = await tempDir();
    await mkdir(join(d, ".dotation", "rules"), { recursive: true });
    await writeFile(
      join(d, ".dotation", "rules", "fr.yaml"),
      `- id: ACME-FR-001
  severity: low
  category: code
  detector: { type: regex, files: ["**/*.ts"], pattern: "TODO SECURITE" }
  text: { fr: { title: A faire, explanation: Note oubliee., fix: Traite-la. } }
`,
    );
    await writeFile(join(d, "a.ts"), "// TODO SECURITE\n");
    const report = await scan(d, { engines: [houseEngine] });
    expect(report.findings.map((f) => f.id)).toEqual(["ACME-FR-001"]);
    expect(report.findings[0]?.title).toBe("A faire");
  });

  it("un pack avec une règle fr seule se charge ; sans en ni fr : erreur", async () => {
    const d = await tempDir();
    const head =
      '- id: ACME-P-001\n  severity: low\n  category: code\n  detector: { type: regex, files: ["*"], pattern: x }\n';
    await writeFile(join(d, "p.yaml"), `${head}  text: { fr: { title: T, explanation: E, fix: F } }\n`);
    expect((await loadRuleDir(d))[0]?.text.en.title).toBe("T");
    await writeFile(join(d, "p.yaml"), `${head}  text: { es: { title: T } }\n`);
    await expect(loadRuleDir(d)).rejects.toThrow(RuleError);
  });

  it("un dossier absent ne gêne pas", async () => {
    expect(await loadRules(["/dossier/inexistant"])).not.toHaveLength(0);
  });
});

describe("règles maison sur la fixture vulnérable", () => {
  it("chaque règle livrée se déclenche (dépôt git, .env et clé versionnés)", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const report = await scan(repo, { engines: [houseEngine] });
    const ids = new Set(report.findings.map((f) => f.id));
    const all = (await loadRuleDir(BUILTIN_RULES_DIR)).map((r) => r.id);
    // DOT-DEP-001 (lockfile absent) : la fixture garde son package-lock.json pour OSV ; testée dans owasp.test.ts.
    const elsewhere = new Set(["DOT-DEP-001"]);
    expect([...all].filter((id) => !ids.has(id) && !elsewhere.has(id))).toEqual([]);
    expect(report.findings.every((f) => f.engine === "house")).toBe(true);
  });

  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const report = await scan(repo, { engines: [houseEngine] });
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
    const r = await scan(d, { engines: [houseEngine] });
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

describe("masquage des variables publiques", () => {
  // Faux secrets assemblés pour ne pas déclencher les scanners de fuite du dépôt.
  const FAKE_LIVE = ["sk", "live", "FAKEdotationPublicVar0000"].join("_");
  const FAKE_JWT = ["eyJ", "hbGciOiJIUzI1NiJ9", "ZmFrZS1kb3RhdGlvbg", "ZmFrZVNpZ25hdHVyZQ"].join(".");

  it("la valeur d'une variable publique n'apparaît ni en pretty, ni en JSON, ni en SARIF", async () => {
    const d = await tempDir();
    await writeFile(
      join(d, ".env"),
      `NEXT_PUBLIC_SECRET_TOKEN=${FAKE_LIVE}\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${FAKE_JWT}\n`,
    );
    const report = await scan(d, { engines: [houseEngine] });
    const hits = report.findings.filter((f) => f.id === "DOT-SEC-004");
    expect(hits.map((f) => f.line)).toEqual([1, 2]);
    const outputs = [
      renderPretty(report, { all: true, color: false }),
      renderJson(report),
      JSON.stringify(toSarif(report)),
    ];
    for (const [i, out] of outputs.entries()) {
      if (i < 2) expect(out).toContain("NEXT_PUBLIC_SECRET_TOKEN"); // SARIF ne porte pas d'extrait
      for (const v of [FAKE_LIVE, FAKE_JWT, "hbGciOiJIUzI1NiJ9", "FAKEdotationPublicVar0000"]) {
        expect(out).not.toContain(v);
      }
    }
  });

  it("filet de sécurité : une règle « secret » sans groupe capturé masque la valeur affectée", async () => {
    const d = await tempDir();
    await writeFile(join(d, "client.ts"), `"use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n`);
    await mkdir(join(d, "app"));
    await writeFile(join(d, "app/page.tsx"), `"use client";\nconst service_role = "${FAKE_JWT}";\n`);
    const report = await scan(d, { engines: [houseEngine] });
    const sec5 = report.findings.filter((f) => f.id === "DOT-SEC-005");
    expect(sec5.map((f) => f.file).sort()).toEqual(["app/page.tsx", "client.ts"]);
    expect(JSON.stringify(report)).not.toContain(FAKE_JWT);
    // une lecture de variable d'environnement reste lisible
    expect(sec5.find((f) => f.file === "client.ts")?.snippet).toContain("process.env.SUPABASE_SERVICE_ROLE_KEY");
  });

  // Chaque ligne : [nom du fichier, contenu, valeurs factices qui ne doivent apparaître nulle part, règle attendue]
  const CASES: [string, string, string[], string][] = [
    [
      ".env",
      "NEXT_PUBLIC_A_SECRET=FAKEaaaa1111bbbb2222 NEXT_PUBLIC_B_SECRET=FAKEbbbb3333",
      ["FAKEaaaa1111", "FAKEbbbb3333"],
      "DOT-SEC-004",
    ],
    [
      "a.ts",
      'const c = { NEXT_PUBLIC_API_SECRET: "FAKEg1g1g1", NEXT_PUBLIC_DB_PASSWORD: "FAKEh2h2h2" };',
      ["FAKEg1g1g1", "FAKEh2h2h2"],
      "DOT-SEC-004",
    ],
    [
      "b.ts",
      'const d = { "import.meta.env.VITE_SECRET_J": JSON.stringify("FAKEj3j3j3") };',
      ["FAKEj3j3j3"],
      "DOT-SEC-004",
    ],
    [".env", 'NEXT_PUBLIC_SECRET_K="FAKEcc cc3333 cccc"', ["FAKEcc", "cc3333", "cccc"], "DOT-SEC-004"],
    ["c.ts", 'const e = process.env.NEXT_PUBLIC_SECRET_I ?? "FAKEi4i4i4";', ["FAKEi4i4i4"], "DOT-SEC-004"],
    ["d.ts", 'const f = process.env.VITE_OPENAI_API_KEY || "FAKEo5o5o5";', ["FAKEo5o5o5"], "DOT-AI-001"],
    [".env", "NEXT_PUBLIC_PASSWORD=Fk9q2", ["Fk9q2"], "DOT-SEC-004"],
    ["e.ts", "const g = { NEXT_PUBLIC_SECRET_L: `FAKEl6l6l6` };", ["FAKEl6l6l6"], "DOT-SEC-004"],
    ["f.ts", "const h = { NEXT_PUBLIC_SECRET_M: 'FAKEm7m7m7' };", ["FAKEm7m7m7"], "DOT-SEC-004"],
    [".env", "export NEXT_PUBLIC_SECRET_N=FAKEn8n8n8", ["FAKEn8n8n8"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_SECRET_P: 'FAKEp9p9p9'", ["FAKEp9p9p9"], "DOT-SEC-004"],
    [
      ".env",
      "NEXT_PUBLIC_SECRET_Q=FAKEq1q1q1\r\nNEXT_PUBLIC_SECRET_R=FAKEr2r2r2\r\n",
      ["FAKEq1q1q1", "FAKEr2r2r2"],
      "DOT-SEC-004",
    ],
    [
      "g.ts",
      `const i = { NEXT_PUBLIC_SECRET_S: "${"x".repeat(150)}FAKEs3s3s3s3s3s3" };`,
      ["FAKEs3s3s3s3s3s3"],
      "DOT-SEC-004",
    ],
    // Deuxième relecture : caractères spéciaux, valeurs en « $ », guillemet isolé plus tôt sur la ligne.
    [".env", "NEXT_PUBLIC_PASSWORD_E=abc#FAKEe5e5e5", ["FAKEe5e5e5"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_F=it'sFAKEf6f6f6", ["FAKEf6f6f6"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_G=pa;FAKEg7g7g7", ["FAKEg7g7g7"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_L=x,FAKEl8l8l8", ["FAKEl8l8l8"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_K=(FAKEk9k9k9)", ["FAKEk9k9k9"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_I=$FAKEi1i1i1", ["FAKEi1i1i1"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_H=$Abc123!FAKEh2h2h2", ["FAKEh2h2h2", "Abc123"], "DOT-SEC-004"],
    ["h.ts", "const re = /'/; const NEXT_PUBLIC_SECRET_X = 'FAKEw3w3w3';", ["FAKEw3w3w3"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_SECRET_URL=https://user:FAKEu4u4u4@db.example.com", ["FAKEu4u4u4"], "DOT-SEC-004"],
    ["i.ts", "const t = { NEXT_PUBLIC_SECRET_Y: `${base}FAKEy5y5y5` };", ["FAKEy5y5y5"], "DOT-SEC-004"],
    // Troisième relecture : deux valeurs sur une ligne .mcp.json, forme setenv, deux-points dans la valeur.
    [
      ".mcp.json",
      '{"mcpServers": {"acme": {"command": "acme-mcp", "env": { "ACME_API_TOKEN": "FAKEaaaa1111aaaa2222", "OTHER_SECRET_KEY": "FAKEbbbb3333bbbb4444" }}}}',
      ["FAKEaaaa1111", "FAKEbbbb3333"],
      "DOT-MCP-002",
    ],
    [".envrc", "setenv NEXT_PUBLIC_PASSWORD FAKEccpw", ["FAKEccpw"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_SECRET_C=abcd1234efgh:FAKEc7c7", ["abcd1234efgh", "FAKEc7c7"], "DOT-SEC-004"],
    [".env", 'NEXT_PUBLIC_SECRET_D="FAKEdd dd4444:x"', ["FAKEdd", "dd4444"], "DOT-SEC-004"],
    // Quatrième relecture : valeurs déguisées en noms, en références ou en clés ; deux mots sans séparateur.
    [".env", "NEXT_PUBLIC_SECRET_A=FAKE_BBB_CCC:FAKEtail1", ["FAKE_BBB_CCC", "FAKEtail1"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_SECRET_B=FAKE_DDD_EEE=", ["FAKE_DDD_EEE"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_C=hunter-vars.FAKEvarsPart9", ["FAKEvarsPart9", "hunter"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_E=a/process.env.FAKEprocPart9", ["FAKEprocPart9"], "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_PASSWORD_P=process.env.FAKEprocStart9", ["FAKEprocStart9"], "DOT-SEC-004"],
    [".env", 'NEXT_PUBLIC_SECRET_F={"FAKEkeyAsSecret9":1}', ["FAKEkeyAsSecret9"], "DOT-SEC-004"],
    [".envrc", "NEXT_PUBLIC_PASSWORD FAKEtwoWords", ["FAKEtwoWords"], "DOT-SEC-004"],
    [".env", 'NEXT_PUBLIC_SECRET_G="FAKE ABC_DEF=ghi"', ["ABC_DEF", "ghi"], "DOT-SEC-004"],
    // Cinquième relecture : texte avant le premier séparateur ou guillemet.
    [".envrc", "setenv NEXT_PUBLIC_PASSWORD FAKEpwA1 # TODO: rotate", ["FAKEpwA1"], "DOT-SEC-004"],
    [".envrc", "setenv NEXT_PUBLIC_PASSWORD FAKEpwB2 # don't commit", ["FAKEpwB2"], "DOT-SEC-004"],
    [
      "m.ts",
      '{"FAKEkeyLeft3": "x", "NEXT_PUBLIC_SECRET_H": "FAKEh4h4h4"}',
      ["FAKEkeyLeft3", "FAKEh4h4h4"],
      "DOT-SEC-004",
    ],
  ];

  it.each([
    ["k.ts", "const u = process.env.NEXT_PUBLIC_SECRET_KEY2;", "process.env.NEXT_PUBLIC_SECRET_KEY2", "DOT-SEC-004"],
    [".env", "NEXT_PUBLIC_SECRET_V2=FAKEv8v8v8", "NEXT_PUBLIC_SECRET_V2=", "DOT-SEC-004"],
    ["l.js", 'module.exports = { env: { NEXT_PUBLIC_API_SECRET: "FAKEw9w9w9" } };', "module.exports =", "DOT-SEC-004"],
  ])("masquage lisible : le nom reste visible (%s)", async (file, content, visible, ruleId) => {
    const d = await tempDir();
    await writeFile(join(d, file), content);
    const report = await scan(d, { engines: [houseEngine] });
    const f = report.findings.find((x) => x.id === ruleId);
    expect(f?.snippet).toContain(visible);
    expect(f?.snippet).not.toMatch(/FAKE[a-z]\d/);
  });

  it("masquage par refus par défaut : nom et références process.env lisibles, valeur masquée", async () => {
    const d = await tempDir();
    await writeFile(join(d, "j.ts"), 'const e = process.env.NEXT_PUBLIC_SECRET_Z ?? "FAKEz6z6z6";');
    const report = await scan(d, { engines: [houseEngine] });
    const f = report.findings.find((x) => x.id === "DOT-SEC-004");
    expect(f?.snippet).toContain("process.env.NEXT_PUBLIC_SECRET_Z");
    expect(f?.snippet).not.toContain("FAKEz6z6z6");
  });

  it.each(CASES)("contournements : %s %#", async (file, content, values, ruleId) => {
    const d = await tempDir();
    await writeFile(join(d, file), content);
    const report = await scan(d, { engines: [houseEngine] });
    expect(report.findings.some((f) => f.id === ruleId)).toBe(true);
    const outputs = [
      renderPretty(report, { all: true, color: false }),
      renderJson(report),
      JSON.stringify(toSarif(report)),
    ];
    for (const out of outputs) for (const v of values) expect(out).not.toContain(v);
  });
});
