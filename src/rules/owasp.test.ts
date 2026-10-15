// biome-ignore-all lint/suspicious/noTemplateCurlyInString: ces chaînes sont du code analysé, pas des gabarits
// Règles alignées sur les référentiels OWASP (Top 10 2025, API 2023, LLM 2025, MCP 2025, NHI 2025, CI/CD).
// Pour chaque règle : un cas qui doit sortir, et les cas proches qui ne doivent pas sortir (faux positifs).
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { houseEngine } from "../engines/house.js";
import { scan } from "../scan.js";
import { fixtureRepo, tempDir } from "../test/helpers.js";

/** Écrit des fichiers dans un dossier neuf et renvoie les constats « id fichier:ligne » des règles maison (préfixe d'id). */
async function hits(files: Record<string, string>, prefix = ""): Promise<string[]> {
  const d = await tempDir();
  for (const [p, content] of Object.entries(files)) {
    await mkdir(dirname(join(d, p)), { recursive: true });
    await writeFile(join(d, p), content);
  }
  const r = await scan(d, { engines: [houseEngine] });
  return r.findings.filter((f) => f.id.startsWith(prefix)).map((f) => `${f.id} ${f.file}:${f.line}`);
}

describe("A01 contrôle d'accès (fixture vulnérable)", () => {
  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-ACC-006")).toEqual(["app/api/orders/route.ts:4"]);
    expect(at("DOT-ACC-007")).toEqual(["app/actions.ts:5"]);
    expect(at("DOT-ACC-008")).toEqual(["routes/files.js:7"]);
    expect(at("DOT-ACC-009")).toEqual(["routes/files.js:11"]);
    expect(at("DOT-ACC-010")).toEqual(["routes/files.js:14"]);
  });
});

describe("A01 : pas de faux positif", () => {
  const write = "await prisma.order.create({ data: {} });\n";
  it("route en lecture seule, route qui vérifie la session, webhook signé", async () => {
    expect(
      await hits({
        "app/api/a/route.ts": `export async function GET() {\n  return Response.json(await prisma.order.findMany());\n}\n`,
        "app/api/b/route.ts": `import { auth } from "@/auth";\nexport async function POST() {\n  const s = await auth();\n  ${write}}\n`,
        "app/api/c/route.ts": `export async function POST(req: Request) {\n  stripe.webhooks.constructEvent(await req.text(), sig, secret);\n  ${write}}\n`,
      }),
    ).toEqual([]);
  });
  it("Server Action sans écriture, fichier sans « use server »", async () => {
    expect(
      await hits({
        "a.ts": `"use server";\nexport async function list() {\n  return prisma.order.findMany();\n}\n`,
        "b.ts": `export async function save() {\n  ${write}}\n`,
      }),
    ).toEqual([]);
  });
  it("URL fixe ou construite côté serveur, redirection relative vérifiée, fichier connu", async () => {
    expect(
      await hits({
        "a.js": [
          'await fetch("https://api.example.com/x");',
          "await fetch(`${API}/users/${id}`);",
          'const n = searchParams.get("next"); if (n.startsWith("/")) redirect(n);',
          'redirect(searchParams.get("next") ?? "/");',
          "res.sendFile(path.join(__dirname, 'public', 'index.html'));",
          "",
        ].join("\n"),
      }),
    ).toEqual(["DOT-ACC-009 a.js:4"]);
  });
});

describe("LLM Top 10 (fixture vulnérable)", () => {
  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-AI-001")).toEqual(["lib/ai.ts:6"]);
    expect(at("DOT-AI-002")).toEqual(["lib/ai.ts:7"]);
    expect(at("DOT-AI-003")).toEqual(["app/chat/page.tsx:7"]);
    expect(at("DOT-AI-004")).toEqual(["lib/ai.ts:16"]);
    expect(at("DOT-AI-005")).toEqual(["lib/ai.ts:13"]);
    expect(at("DOT-AI-006")).toEqual(["lib/ai.ts:11"]);
  });
});

describe("LLM Top 10 : pas de faux positif", () => {
  it("exec sans SDK d'IA, innerHTML d'une constante ou nettoyé, prompt système fixe", async () => {
    expect(
      await hits(
        {
          "build.ts": 'import { execSync } from "node:child_process";\nexecSync("npm run build");\n',
          "a.tsx": [
            'import { useChat } from "ai/react";',
            'el.innerHTML = "<b>ok</b>";',
            "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(m.content) }} />;",
            "",
          ].join("\n"),
          "b.ts": [
            'import OpenAI from "openai";',
            "const r = await openai.chat.completions.create({ max_tokens: 200, messages: [",
            '  { role: "system", content: `Date : ${today}` },',
            '  { role: "user", content: req.body.q },',
            "] });",
            "",
          ].join("\n"),
          ".env.local": "OPENAI_API_KEY=\nNEXT_PUBLIC_SITE_URL=https://example.com\n",
        },
        "DOT-AI",
      ),
    ).toEqual([]);
  });
  it("Python : f-string dans le message système", async () => {
    expect(
      await hits({
        "app.py": [
          "from openai import OpenAI",
          'messages = [{"role": "system", "content": f"Answer about {request.json[\'topic\']}"}]',
          "client.chat.completions.create(model=m, messages=messages, max_tokens=100)",
          "",
        ].join("\n"),
      }),
    ).toEqual(["DOT-AI-005 app.py:2"]);
  });
});

describe("CI/CD Top 10 (fixture vulnérable)", () => {
  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    const wf = ".github/workflows/triage.yml";
    expect(at("DOT-CI-001")).toEqual([`${wf}:13`]);
    expect(at("DOT-CI-002")).toEqual([`${wf}:10`]);
    expect(at("DOT-CI-003")).toEqual([`${wf}:15`]);
    expect(at("DOT-CI-004")).toEqual([`${wf}:12`]);
    expect(at("DOT-CI-005")).toEqual([`${wf}:5`]);
    expect(at("DOT-CI-006")).toEqual([".github/workflows/build.yml:2"]);
    expect(at("DOT-CI-007")).toEqual([`${wf}:16`]);
  });
});

describe("CI/CD Top 10 : pas de faux positif", () => {
  it("action locale, image docker, ref sans pull_request_target, expressions sûres", async () => {
    expect(
      await hits(
        {
          ".github/workflows/a.yml": [
            "on: pull_request",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  a:",
            "    steps:",
            "      - uses: ./.github/actions/setup",
            "      - uses: docker://alpine:3.20",
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}",
            "      - run: echo ${{ github.event.pull_request.number }} ${{ github.sha }}",
            '      - run: echo "//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}" > .npmrc',
            '      - run: echo "${{ secrets.GHCR_TOKEN }}" | docker login ghcr.io -u bot --password-stdin',
            "      - run: echo token=${{ secrets.NPM_TOKEN }}",
            "",
          ].join("\n"),
        },
        "DOT-CI",
      ),
    ).toEqual(["DOT-CI-007 .github/workflows/a.yml:15"]);
  });
});

describe("MCP Top 10 : configuration des agents", () => {
  it("fixture vulnérable", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const mcp = r.findings.filter((f) => f.id.startsWith("DOT-MCP"));
    expect(mcp.map((f) => `${f.id} ${f.file}:${f.line}`)).toEqual([
      "DOT-MCP-002 .mcp.json:6",
      "DOT-MCP-003 .mcp.json:8",
      "DOT-MCP-001 .mcp.json:5",
    ]);
    expect(JSON.stringify(mcp)).not.toContain("FakeDotationMcpToken0000");
  });
  it("JSONC de VS Code (commentaires, virgule finale), ${input:…}, uvx figé, version flottante @latest", async () => {
    expect(
      await hits(
        {
          ".vscode/mcp.json": [
            "{",
            "  // serveurs du projet",
            '  "servers": {',
            '    "pg": { "command": "uvx", "args": ["mcp-server-postgres==0.6.2"], "env": { "PG_PASSWORD": "${input:pg}" } },',
            '    "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@latest", "."] },',
            "  },",
            "}",
            "",
          ].join("\n"),
        },
        "DOT-MCP",
      ),
    ).toEqual(["DOT-MCP-001 .vscode/mcp.json:5"]);
  });
});

describe("A04, A07, A08 (fixture vulnérable)", () => {
  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-INT-001")).toEqual(["api/webhook.ts:6"]);
    expect(at("DOT-AUTH-001")).toEqual(["lib/tokens.ts:12"]);
    expect(at("DOT-AUTH-002")).toEqual(["lib/tokens.ts:9"]);
    expect(at("DOT-CRY-001")).toEqual(["lib/tokens.ts:5"]);
    expect(at("DOT-CRY-002")).toEqual(["lib/tokens.ts:6"]);
    expect(at("DOT-INT-002")).toEqual(["routes/users.js:4"]);
    expect(at("DOT-AUTH-003")).toEqual(["app/login/page.tsx:4"]);
  });
});

describe("A04, A07, A08 : pas de faux positif", () => {
  it("aléa d'affichage, hachage d'un fichier, decode dans un composant client, champs choisis", async () => {
    expect(
      await hits(
        {
          "a.ts": [
            "const colorIndex = Math.floor(Math.random() * 6);",
            "const etag = createHash('sha256').update(fileContent).digest('hex');",
            "await prisma.user.update({ where: { id }, data: { name: body.name } });",
            'localStorage.setItem("theme", "dark");',
            "",
          ].join("\n"),
          "b.tsx": '"use client";\nconst claims = jwtDecode(token);\n',
          "c.py": "token = secrets.token_urlsafe(32)\npayload = jwt.decode(t, key, algorithms=['HS256'])\n",
        },
        "DOT-",
      ),
    ).toEqual([]);
  });
});

describe("A02 configuration et conteneurs (fixture vulnérable)", () => {
  it("emplacements exacts", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-CFG-004")).toEqual(["Dockerfile:2"]);
    expect(at("DOT-CFG-005")).toEqual(["Dockerfile:2"]);
    expect(at("DOT-CFG-006")).toEqual(["docker-compose.yml:6"]);
    expect(at("DOT-CFG-007")).toEqual(["next.config.js:3"]);
    expect(at("DOT-CFG-008")).toEqual(["lib/session.ts:5"]);
  });
});

describe("A02 : pas de faux positif", () => {
  it("étape de construction nommée, utilisateur numérique, ports d'application, secure conditionnel", async () => {
    expect(
      await hits(
        {
          Dockerfile: "FROM golang:1.26 AS build\nFROM build AS test\nFROM gcr.io/distroless/static:nonroot\n",
          "api/Dockerfile": "FROM python:3.13-slim\nUSER 10001\n",
          "compose.yaml": 'services:\n  web:\n    ports:\n      - "3000:3000"\n      - "127.0.0.1:6379:6379"\n',
          "c.ts": "res.cookie('sid', v, { httpOnly: true, secure: isProd });\n",
        },
        "DOT-CFG",
      ),
    ).toEqual([]);
  });
});

describe("A03 chaîne d'approvisionnement", () => {
  it("fixture vulnérable", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-DEP-001")).toEqual([]);
    expect(at("DOT-DEP-002")).toEqual(["pyproject.toml:0"]);
    expect(at("DOT-DEP-003")).toEqual(["package.json:9"]);
    expect(at("DOT-DEP-004")).toEqual(["api/requirements.txt:3"]);
    expect(at("DOT-DEP-005")).toEqual(["package.json:10"]);
  });
  it("lockfile absent : seulement à la racine d'un projet entier, et seulement s'il y a des dépendances", async () => {
    const pkg = '{\n  "dependencies": {\n    "express": "^4.21.2"\n  }\n}\n';
    expect(await hits({ "package.json": pkg }, "DOT-DEP")).toEqual(["DOT-DEP-001 package.json:0"]);
    expect(await hits({ "package.json": pkg, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" }, "DOT-DEP")).toEqual([]);
    expect(await hits({ "package.json": '{ "name": "x", "dependencies": {} }\n' }, "DOT-DEP")).toEqual([]);
    expect(await hits({ "packages/a/package.json": pkg }, "DOT-DEP")).toEqual([]);
  });
  it("champs qui ne sont pas des dépendances, requirements figé ou inclus", async () => {
    expect(
      await hits(
        {
          "package.json":
            '{\n  "version": "x",\n  "engines": { "node": ">=22" },\n  "dependencies": { "a": "^1.0.0" }\n}\n',
          "package-lock.json": "{}\n",
          "requirements.txt": "-r base.txt\n-e .\nflask==3.0.3\n# commentaire\ngit+https://github.com/x/y@v1#egg=y\n",
        },
        "DOT-DEP",
      ),
    ).toEqual([]);
  });
});

describe("A09, A10 erreurs et journaux", () => {
  it("fixture vulnérable", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await scan(repo, { engines: [houseEngine] });
    const at = (id: string) => r.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(at("DOT-ERR-001")).toEqual(["routes/errors.js:10"]);
    expect(at("DOT-ERR-002")).toEqual(["routes/errors.js:6"]);
    expect(at("DOT-LOG-001")).toEqual(["routes/errors.js:7"]);
  });
  it("pas de faux positif : catch hors code sensible, compteur nommé token…, message générique", async () => {
    expect(
      await hits(
        {
          "theme.ts": "try { localStorage.clear(); } catch {}\n",
          "a.ts": [
            'console.log("tokens restants :", tokenCount);',
            'console.log("mode", process.env.NODE_ENV);',
            "res.status(500).json({ error: 'internal error' });",
            "",
          ].join("\n"),
        },
        "DOT-",
      ),
    ).toEqual([]);
  });
});

describe("validation sur de vrais dépôts : bruit corrigé", () => {
  it("RLS Supabase : pas dans un projet Postgres + Drizzle sans Supabase", async () => {
    const sql = 'CREATE TABLE IF NOT EXISTS "users" (\n  "id" serial PRIMARY KEY\n);\n';
    expect(
      await hits(
        { "lib/db/migrations/0000_init.sql": sql, "package.json": '{ "dependencies": { "drizzle-orm": "0.44.0" } }\n' },
        "DOT-ACC-004",
      ),
    ).toEqual([]);
    expect(
      await hits(
        { "db/schema.sql": sql, "package.json": '{ "dependencies": { "@supabase/supabase-js": "2.45.0" } }\n' },
        "DOT-ACC-004",
      ),
    ).toEqual(["DOT-ACC-004 db/schema.sql:1"]);
  });
  it("mot de passe : un libellé d'enum n'en est pas un, un mot de passe de seed si", async () => {
    expect(
      await hits(
        { "schema.ts": "  UPDATE_PASSWORD = 'UPDATE_PASSWORD',\n", "seed.ts": "const password = 'admin123';\n" },
        "DOT-SEC-003",
      ),
    ).toEqual(["DOT-SEC-003 seed.ts:1"]);
  });
  it("monorepo npm : « * » vers un paquet du dépôt", async () => {
    expect(
      await hits(
        {
          "package.json": '{\n  "workspaces": ["src/*"],\n  "dependencies": {\n    "@acme/server": "*"\n  }\n}\n',
          "package-lock.json": "{}\n",
        },
        "DOT-DEP",
      ),
    ).toEqual([]);
  });
  it("un constat par workflow pour les actions non épinglées, dernière étape FROM du Dockerfile", async () => {
    const wf =
      "permissions: {}\non: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n      - uses: a/b@v1\n      - uses: c/d@main\n";
    expect(await hits({ ".github/workflows/a.yml": wf }, "DOT-CI")).toEqual([
      "DOT-CI-001 .github/workflows/a.yml:8",
      "DOT-CI-002 .github/workflows/a.yml:6",
    ]);
    expect(
      await hits(
        { Dockerfile: "FROM node:22 AS build\nRUN npm ci\nFROM node:22-slim\nCMD node a.js\n" },
        "DOT-CFG-004",
      ),
    ).toEqual(["DOT-CFG-004 Dockerfile:3"]);
  });
});

describe("Supabase en profondeur (DOT-ACC-011 à 014)", () => {
  const SB = { "package.json": '{ "dependencies": { "@supabase/supabase-js": "2.45.0" } }\n' };
  const at = async (sql: string, files: Record<string, string> = SB) =>
    hits({ ...files, "supabase/migrations/1.sql": sql }, "DOT-ACC-01");

  it("fixtures : vulnérable et saine", async () => {
    const bad = await scan(await fixtureRepo("vulnerable-app"), { engines: [houseEngine] });
    const loc = (id: string) => bad.findings.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`);
    expect(loc("DOT-ACC-011")).toEqual(["supabase/migrations/0002_policies.sql:19"]);
    expect(loc("DOT-ACC-015")).toEqual(["supabase/migrations/0002_policies.sql:3"]);
    expect(loc("DOT-ACC-012")).toEqual(["supabase/migrations/0002_policies.sql:8"]);
    expect(loc("DOT-ACC-013")).toEqual(["supabase/migrations/0002_policies.sql:14"]);
    expect(loc("DOT-ACC-014")).toEqual(["supabase/migrations/0002_policies.sql:17"]);
    const good = await scan(await fixtureRepo("clean-app"), { engines: [houseEngine] });
    expect(good.findings.filter((f) => /^DOT-ACC-01[1-5]$/.test(f.id))).toEqual([]);
  });
  it("policy : multi-ligne, casse, rôles", async () => {
    expect(await at('CREATE POLICY "a" ON t\n  FOR ALL\n  USING (\n true )\n  WITH CHECK (TRUE);')).toEqual([
      "DOT-ACC-011 supabase/migrations/1.sql:1",
    ]);
    expect(await at("create policy a on t to anon with check (true);")).toHaveLength(1);
    expect(await at("create policy a on t to service_role using (true);")).toEqual([]);
    expect(await at('create policy a on t to "service_role" using (true);')).toEqual([]);
    expect(await at('create policy a on t to "service_role" using (true);')).toEqual([]);
    expect(await at("create policy a on t using (auth.uid() = id);")).toEqual([]);
  });
  it("hors projet Supabase : rien", async () => {
    expect(await hits({ "db/x.sql": "create policy a on t using (true);" }, "DOT-ACC-01")).toEqual([]);
  });
  it("fonction et vue : qualification de schéma", async () => {
    expect(
      await at("create function private.f() returns int language sql security definer as $$ select 1; $$;"),
    ).toEqual([]);
    expect(
      await at("create or replace function f() returns int language sql security definer as $$ select 1; $$;"),
    ).toEqual(["DOT-ACC-012 supabase/migrations/1.sql:1"]);
    expect(await at("create view private.v as select 1;")).toEqual([]);
    expect(await at("create view v with (security_invoker = on) as select 1;")).toEqual([]);
  });
  it("policy en lecture seule : gravité moyenne (DOT-ACC-015), écriture : haute (DOT-ACC-011)", async () => {
    const one = (sev: string) => async (sql: string) => {
      const d = await tempDir();
      await mkdir(join(d, "supabase/migrations"), { recursive: true });
      await writeFile(join(d, "package.json"), SB["package.json"]);
      await writeFile(join(d, "supabase/migrations/1.sql"), sql);
      const r = await scan(d, { engines: [houseEngine] });
      return r.findings.filter((f) => f.severity === sev && /^DOT-ACC-01[15]$/.test(f.id)).map((f) => f.id);
    };
    expect(await one("medium")("create policy a on t for select using (true);")).toEqual(["DOT-ACC-015"]);
    expect(await one("high")("create policy a on t for select using (true);")).toEqual([]);
    expect(await one("high")("create policy a on t for update using (true);")).toEqual(["DOT-ACC-011"]);
    expect(await at("create policy a on t for insert with check (true);")).toEqual([
      "DOT-ACC-011 supabase/migrations/1.sql:1",
    ]);
    expect(await at("create policy a on t for delete using (true);")).toHaveLength(1);
    expect(await at("create policy a on t for all using (true);")).toEqual(["DOT-ACC-011 supabase/migrations/1.sql:1"]);
  });
  it("découpe : commentaire, chaîne, identifiant, $tag$ non fermés ou imbriqués", async () => {
    const { splitSql } = await import("./detectors.js");
    expect(splitSql("select 'a;b; select 2")).toHaveLength(1);
    expect(splitSql("select 1; /* a; b; c")).toHaveLength(2);
    expect(splitSql('select "a;b"; select 2')).toHaveLength(2);
    expect(splitSql('select "a;b; select 2')).toHaveLength(1);
    expect(splitSql("select 1; select $a$ x; y; ")).toHaveLength(2);
    expect(splitSql("select $a$ x $b$ ; $b$ ; $a$; select 2")).toHaveLength(2);
    expect(splitSql("select /* a /* b; */ c; */ 1; select 2")).toHaveLength(2);
    expect(splitSql("select E'it\\'s;'; select 2")).toHaveLength(2);
    expect(splitSql("select 'it\\'; select 2")).toHaveLength(2);
    const lines = splitSql("select 1;\n\n/* x\n*/ select 2;");
    expect(lines.map((s) => s.line)).toEqual([1, 3]);
    // une policy après un commentaire non fermé n'est pas une instruction
    expect(await at("select 1; /* ouvert ; create policy a on t using (true);")).toEqual([]);
    expect(
      await at("create policy a on t using (true); select 'ouvert ; create policy b on t using (true);"),
    ).toHaveLength(1);
  });
  it("commentaire d'en-tête : l'instruction est quand même analysée, ligne exacte", async () => {
    expect(await at("/* migration */\n-- note\n/* /* x */ y */ create policy a on t using (true);")).toEqual([
      "DOT-ACC-011 supabase/migrations/1.sql:3",
    ]);
  });
  it("grosse fonction security definer : en-tête toujours évalué", async () => {
    const body = "select 1; ".repeat(5000);
    expect(await at(`create function f() returns int language sql security definer as $$ ${body} $$;`)).toEqual([
      "DOT-ACC-012 supabase/migrations/1.sql:1",
    ]);
    expect(
      await at(`create function f() returns int language sql security definer set search_path = '' as $$ ${body} $$;`),
    ).toEqual([]);
    expect(
      await at(`create function f() returns int as $$ ${body} $$ language sql security definer set search_path = '';`),
    ).toEqual([]);
    expect(
      await at(
        "create function f() returns int security definer set search_path = pg_catalog, public as $$ select 1 $$;",
      ),
    ).toEqual([]);
  });
  it("buckets : variantes", async () => {
    const flagged = ["DOT-ACC-013 supabase/migrations/1.sql:1"];
    expect(await at("insert into storage.buckets (id, public) values ('a', true);")).toEqual(flagged);
    expect(await at("insert into storage.buckets (public, id) values (true, 'a');")).toEqual(flagged);
    expect(await at("insert into storage.buckets (id, name, public) values ('a', lower('A,b'), TRUE);")).toEqual(
      flagged,
    );
    expect(await at("insert into storage.buckets (id, public) values ('a', false);")).toEqual([]);
    expect(await at("insert into storage.buckets (id, public, file_size_limit) values ('a', false, true);")).toEqual(
      [],
    );
    expect(await at("update storage.buckets set public = true where id = 'a';")).toEqual(flagged);
    expect(await at("update storage.buckets set public = false where id = 'a';")).toEqual([]);
    expect(await at("select storage.create_bucket('a', public => true);")).toEqual(flagged);
    expect(await at("select storage.create_bucket('a', public => false);")).toEqual([]);
  });
  it("vues : security_invoker, vues matérialisées", async () => {
    expect(await at("create view v with (security_invoker) as select 1;")).toEqual([]);
    expect(await at("create view v with (security_invoker = true) as select 1;")).toEqual([]);
    expect(await at("create view v with (security_barrier, security_invoker = on) as select 1;")).toEqual([]);
    expect(await at("create view v with (security_invoker = false) as select 1;")).toEqual([
      "DOT-ACC-014 supabase/migrations/1.sql:1",
    ]);
    expect(await at("create or replace view v as select 1;")).toHaveLength(1);
    expect(await at("create materialized view v as select 1;")).toEqual([]);
  });
  it("$tag$ non fermés : 1 Mo en moins de 300 ms pour les 4 règles", async () => {
    const { detect } = await import("./detectors.js");
    const { loadRuleDir, BUILTIN_RULES_DIR } = await import("./loader.js");
    const rules = (await loadRuleDir(BUILTIN_RULES_DIR)).filter((r) => /^DOT-ACC-01[1-5]$/.test(r.id));
    const noise = "$a$b$c$".repeat(150_000);
    const inputs = [
      `create policy x on t using (true) ${noise}`,
      `insert into storage.buckets (id, public) values ('a', true) ${noise}`,
      `create function f() returns int security definer as ${noise}`,
      `create view v as ${noise}`,
      noise,
      "$a$ ".repeat(250_000),
    ];
    for (const sql of inputs) {
      const t = performance.now();
      for (const rule of rules) {
        await detect(rule, {
          fileSet: { files: [{ path: "supabase/migrations/1.sql" }] },
          scope: "project",
          content: async () => sql,
        } as never);
      }
      expect(performance.now() - t).toBeLessThan(300);
    }
  });
  it("entrée pathologique de 200 Ko : moins de 200 ms", async () => {
    const { detect } = await import("./detectors.js");
    const { loadRuleDir, BUILTIN_RULES_DIR } = await import("./loader.js");
    const rules = (await loadRuleDir(BUILTIN_RULES_DIR)).filter((r) => /^DOT-ACC-01[1-5]$/.test(r.id));
    const inputs = [
      `create policy ${"a ".repeat(100_000)}`,
      `insert into storage.buckets (${"public ".repeat(30_000)}`,
      `create function ${"x(".repeat(100_000)}`,
      `create view ${"using ( ".repeat(25_000)}`,
    ];
    for (const sql of inputs) {
      const t = performance.now();
      for (const rule of rules) {
        await detect(rule, {
          fileSet: { files: [{ path: "supabase/migrations/1.sql" }] },
          scope: "project",
          content: async () => sql,
        } as never);
      }
      expect(performance.now() - t).toBeLessThan(200);
    }
  });
});

describe("sql-statement : noms et chaînes ne sont pas des commandes", () => {
  const sb = (sql: string) => hits({ "supabase/config.toml": "", "supabase/migrations/1.sql": sql }, "DOT-ACC-01");
  const ids = (r: string[]) => r.map((x) => x.split(" ")[0]);
  it("nom de policy du gabarit Supabase : 015 et non 011", async () => {
    const r = await sb('create policy "Enable read access for all users" on t for select using (true);');
    expect(ids(r)).toEqual(["DOT-ACC-015"]);
  });
  it('policy nommée "for insert" mais for select : 015', async () => {
    const r = await sb('create policy "for insert" on t for select using (true);');
    expect(ids(r)).toEqual(["DOT-ACC-015"]);
  });
  it("« -- » dans une chaîne ou un identifiant ne tronque pas l'instruction", async () => {
    const r = await sb('create policy "a -- b" on t for insert with check (true);');
    expect(ids(r)).toEqual(["DOT-ACC-011"]);
  });
  it("commentaire de bloc au milieu de l'instruction ignoré", async () => {
    const r = await sb("create policy p on t for /* x */ select using (true);");
    expect(ids(r)).toEqual(["DOT-ACC-015"]);
  });
  it("bucket public avec une valeur de 20 000 caractères : moins de 50 ms", async () => {
    const { detect } = await import("./detectors.js");
    const { loadRuleDir, BUILTIN_RULES_DIR } = await import("./loader.js");
    const rule = (await loadRuleDir(BUILTIN_RULES_DIR)).find((r) => r.id === "DOT-ACC-013");
    const input = {
      fileSet: { files: [{ path: "supabase/migrations/1.sql" }] },
      scope: "project",
      content: async () => `insert into storage.buckets (id, name, x, public) values ('a', ${"b".repeat(20_000)}, 1);`,
    } as never;
    const t = performance.now();
    await detect(rule as never, input);
    expect(performance.now() - t).toBeLessThan(50);
  });
});
