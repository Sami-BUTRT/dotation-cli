import { execFile } from "node:child_process";
import { access, mkdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createServer } from "../mcp/server.js";
import { packagePath } from "../paths.js";
import { FAKE_SECRETS, fixtureRepo, git, pathWithoutEngines, tempDir } from "../test/helpers.js";
import { installAgent, mcpLaunch, parseTargets } from "./agent.js";
import { HOOK_MARKER, init } from "./init.js";

const exec = promisify(execFile);
const CLI = packagePath("dist/cli.js");

/** Lance le CLI compilé (npm test compile d'abord) ; renvoie code, stdout, stderr. */
async function cli(args: string[], env: NodeJS.ProcessEnv = {}) {
  try {
    const r = await exec(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: "1", ...env } });
    return { code: 0, stdout: r.stdout, stderr: r.stderr };
  } catch (e) {
    const err = e as { code: number; stdout: string; stderr: string };
    return { code: err.code, stdout: err.stdout, stderr: err.stderr };
  }
}

describe("CLI (dist/cli.js)", () => {
  const noEngines = { PATH: pathWithoutEngines() };

  it("sbom : CycloneDX sur la sortie standard ou dans un fichier", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await cli(["sbom", repo]);
    expect(r.code).toBe(0);
    const bom = JSON.parse(r.stdout) as { bomFormat: string; components: { purl: string }[] };
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.components.map((c) => c.purl)).toContain("pkg:npm/lodash@4.17.15");
    const out = join(await tempDir(), "bom.json");
    const w = await cli(["sbom", repo, "-o", out], { DOTATION_LANG: "en" });
    expect(w.code).toBe(0);
    expect(w.stderr).toMatch(/SBOM written to .*bom\.json: \d+ components\./);
  });

  it("fixture vulnérable : code retour 1, rapport en anglais", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await cli(["scan", repo], noEngines);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("Hygiene score: 0/100");
    expect(r.stdout).toContain("Exit code 1");
    expect(r.stderr).not.toContain("English-only");
    for (const s of FAKE_SECRETS) expect(r.stdout).not.toContain(s);
  });

  it("--lang fr : accepté, ignoré, avis sur stderr, sortie en anglais", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const r = await cli(["scan", repo, "--lang", "fr"], noEngines);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("Note: dotation is now English-only; the 'lang' setting is ignored.");
    expect(r.stderr.split("English-only").length - 1).toBe(1);
    expect(r.stdout).toContain("Hygiene score: 0/100");
    expect(r.stdout).not.toContain("English-only");
  });

  it("DOTATION_LANG=fr : ignoré avec avis ; JSON et SARIF sans avis sur stdout", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const pretty = await cli(["scan", repo], { ...noEngines, DOTATION_LANG: "fr" });
    expect(pretty.stderr).toContain("Note: dotation is now English-only; the 'lang' setting is ignored.");
    const json = await cli(["scan", repo, "--format", "json", "--lang", "fr"], noEngines);
    expect(json.stdout).not.toContain("English-only");
    expect(JSON.parse(json.stdout).lang).toBe("en");
    expect(json.stderr).not.toContain("English-only");
    const sarif = await cli(["scan", repo, "--format", "sarif", "--lang", "fr"], noEngines);
    expect(sarif.stdout).not.toContain("English-only");
    expect(() => JSON.parse(sarif.stdout)).not.toThrow();
  });

  it(".dotation.yml lang: fr : chargé sans erreur, avis, anglais", async () => {
    const repo = await fixtureRepo("clean-app");
    await writeFile(join(repo, ".dotation.yml"), "lang: fr\n");
    const r = await cli(["scan", repo], noEngines);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("Note: dotation is now English-only; the 'lang' setting is ignored.");
    expect(r.stdout).toContain("Hygiene score: 100/100");
  });

  it("projet propre : code retour 0 et 100/100", async () => {
    const repo = await fixtureRepo("clean-app");
    const r = await cli(["scan", repo], noEngines);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Hygiene score: 100/100");
  });

  it("--fail-on critical : un problème « élevé » ne bloque pas", async () => {
    const d = await tempDir();
    await writeFile(join(d, "a.js"), "const agent = new https.Agent({ rejectUnauthorized: false });\n");
    expect((await cli(["scan", d], noEngines)).code).toBe(1);
    expect((await cli(["scan", d, "--fail-on", "critical"], noEngines)).code).toBe(0);
  });

  it("--format json et sarif sur la sortie standard", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const j = JSON.parse((await cli(["scan", repo, "--format", "json"], noEngines)).stdout) as { findings: unknown[] };
    expect(j.findings.length).toBeGreaterThan(10);
    const s = JSON.parse((await cli(["scan", repo, "--format", "sarif"], noEngines)).stdout) as { version: string };
    expect(s.version).toBe("2.1.0");
  });

  it("scan est la commande par défaut ; erreurs d'utilisation : code 2", async () => {
    const d = await tempDir();
    expect((await cli([d], noEngines)).code).toBe(0);
    expect((await cli(["scan", "/chemin/inexistant"], noEngines)).code).toBe(2);
    expect((await cli(["scan", d, "--fail-on", "énorme"], noEngines)).code).toBe(2);
    expect((await cli(["scan", d, "--staged"], noEngines)).code).toBe(2);
  });

  it("--version et --help", async () => {
    const pkg = JSON.parse(await readFile(packagePath("package.json"), "utf8")) as { version: string };
    expect((await cli(["--version"])).stdout.trim()).toBe(pkg.version);
    // Comme après « npm install -g » : lancé par un lien bin/dotation.
    const bin = join(await tempDir(), "dotation");
    await symlink(CLI, bin);
    expect((await exec(process.execPath, [bin, "--version"])).stdout.trim()).toBe(pkg.version);
    // Aide en anglais, même avec une locale française.
    const help = await cli(["--help"], { LANG: "fr_FR.UTF-8" });
    expect(help.stdout).toContain("Scan a project, a folder or a file");
    expect(help.stdout).toContain("scan");
    expect(help.stdout).toContain("init");
    expect(help.stdout).toContain("mcp");
  });
});

describe("dotation init", () => {
  it("crée la configuration, le workflow GitHub et un hook pre-commit exécutable", async () => {
    const d = await tempDir();
    git(d, "init", "-q");
    const res = await init(d, false);
    expect(res.map((r) => r.status)).toEqual(["created", "created", "created"]);
    await access(join(d, ".dotation.yml"));
    const wf = await readFile(join(d, ".github/workflows/dotation.yml"), "utf8");
    expect(wf).toContain("upload-sarif");
    expect(wf).toContain("security-events: write");
    const hook = join(d, ".git/hooks/pre-commit");
    expect(await readFile(hook, "utf8")).toContain("dotation scan --staged");
    expect((await stat(hook)).mode & 0o111).not.toBe(0);
    // Deuxième passage : rien n'est écrasé.
    expect((await init(d, false)).map((r) => r.status)).toEqual(["skipped", "skipped", "skipped"]);
  });

  it("ne remplace pas un hook existant sans --force", async () => {
    const d = await tempDir();
    git(d, "init", "-q");
    await writeFile(join(d, ".git/hooks/pre-commit"), "#!/bin/sh\nnpm test\n");
    const res = await init(d, false);
    expect(res[2]?.status).toBe("hook-exists");
    expect(await readFile(join(d, ".git/hooks/pre-commit"), "utf8")).toBe("#!/bin/sh\nnpm test\n");
    await init(d, true);
    expect(await readFile(join(d, ".git/hooks/pre-commit"), "utf8")).toContain(HOOK_MARKER);
  });

  it("utilise Husky s'il est présent", async () => {
    const d = await tempDir();
    git(d, "init", "-q");
    await import("node:fs/promises").then((fs) => fs.mkdir(join(d, ".husky")));
    const res = await init(d, false);
    expect(res[2]?.path).toBe(join(d, ".husky/pre-commit"));
  });

  it("la configuration générée est valide", async () => {
    const d = await tempDir();
    git(d, "init", "-q");
    await init(d, false);
    expect((await cli(["scan", d], { PATH: pathWithoutEngines() })).code).toBe(0);
  });
});

describe("serveur MCP", () => {
  async function connect() {
    const server = createServer();
    const client = new Client({ name: "test", version: "1.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    return client;
  }

  it("expose cinq outils en lecture seule, avec des instructions pour l'agent", async () => {
    const client = await connect();
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name).sort()).toEqual([
      "explain_rule",
      "list_rules",
      "scan_files",
      "scan_project",
      "scan_staged",
    ]);
    for (const t of tools.tools) expect(t.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    expect(client.getInstructions()).toContain("Never print, copy or move a secret value");
  });

  it("scan_project renvoie score et constats, secrets masqués", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const client = await connect();
    const res = await client.callTool({ name: "scan_project", arguments: { path: repo } });
    const text = (res.content as { type: string; text: string }[])[0]?.text ?? "";
    const data = JSON.parse(text) as { score: number; total: number; blocking: number };
    expect(data.score).toBe(0);
    expect(data.total).toBeGreaterThan(10);
    expect(data.blocking).toBeGreaterThan(0);
    for (const s of FAKE_SECRETS) expect(text).not.toContain(s);
    const missing = await client.callTool({ name: "scan_project", arguments: { path: "/chemin/inexistant" } });
    expect(missing.isError).toBe(true);
  });

  it("scan_files : seulement les fichiers donnés, chemins absolus, secrets masqués", async () => {
    const repo = await fixtureRepo("vulnerable-app");
    const client = await connect();
    const file = join(repo, "lib", "config.ts");
    const res = await client.callTool({ name: "scan_files", arguments: { paths: [file, join(repo, "absent.ts")] } });
    const text = (res.content as { text: string }[])[0]?.text ?? "";
    const data = JSON.parse(text) as {
      total: number;
      findings: { file: string; severity: string }[];
      notFound: string[];
    };
    expect(data.total).toBeGreaterThan(0);
    expect(new Set(data.findings.map((f) => f.file))).toEqual(new Set([file]));
    expect(data.findings[0]?.severity).toBe("critical");
    expect(data.notFound).toEqual([join(repo, "absent.ts")]);
    for (const s of FAKE_SECRETS) expect(text).not.toContain(s);
  });

  it("explain_rule et list_rules", async () => {
    const client = await connect();
    const ok = await client.callTool({ name: "explain_rule", arguments: { id: "dot-acc-004" } });
    expect((ok.content as { text: string }[])[0]?.text).toContain("Supabase table without RLS");
    // Legacy `lang` argument: accepted, ignored.
    const en = await client.callTool({ name: "explain_rule", arguments: { id: "DOT-ACC-004", lang: "fr" } });
    expect((en.content as { text: string }[])[0]?.text).toContain("Supabase table without RLS");
    const ko = await client.callTool({ name: "explain_rule", arguments: { id: "NOPE" } });
    expect(ko.isError).toBe(true);
    const list = JSON.parse(
      ((await client.callTool({ name: "list_rules", arguments: {} })).content as { text: string }[])[0]?.text ?? "[]",
    ) as { id: string }[];
    expect(list.map((r) => r.id)).toContain("DOT-SEC-001");
  });
});

describe("dotation agent", () => {
  const noDotation = { PATH: pathWithoutEngines() } as NodeJS.ProcessEnv;

  it("installe le skill et déclare le serveur MCP sans écraser l'existant", async () => {
    const d = await tempDir();
    const home = await tempDir();
    await writeFile(join(d, ".mcp.json"), JSON.stringify({ mcpServers: { autre: { command: "x" } } }));
    const env = { ...noDotation, HOME: home };
    const res = await installAgent(d, { targets: parseTargets("all"), env });
    expect(res.map((r) => [r.path.replace(d, "."), r.status])).toEqual([
      ["./.claude/skills/dotation/SKILL.md", "created"],
      ["./.mcp.json", "updated"],
      ["./.agents/skills/dotation/SKILL.md", "created"],
      ["./.cursor/mcp.json", "created"],
      ["./.vscode/mcp.json", "created"],
    ]);
    const skill = await readFile(join(d, ".claude/skills/dotation/SKILL.md"), "utf8");
    expect(skill).toMatch(/^---\nname: dotation\ndescription: /);
    const mcp = JSON.parse(await readFile(join(d, ".mcp.json"), "utf8"));
    expect(mcp.mcpServers.autre).toEqual({ command: "x" });
    // dotation absent du PATH : lancement par npx, version figée sur la release GitHub.
    expect(mcp.mcpServers.dotation.command).toBe("npx");
    expect(mcp.mcpServers.dotation.args.join(" ")).toMatch(
      /github\.com\/Sami-BUTRT\/dotation-cli\/releases\/download\/cli-v[\d.]+\/dotation-[\d.]+\.tgz dotation mcp$/,
    );
    const vscode = JSON.parse(await readFile(join(d, ".vscode/mcp.json"), "utf8"));
    expect(vscode.servers.dotation.type).toBe("stdio");
    // Deuxième passage : rien ne change.
    expect((await installAgent(d, { targets: parseTargets("all"), env })).every((r) => r.status === "skipped")).toBe(
      true,
    );
  });

  it("dotation installé : commande directe ; JSON illisible laissé intact ; --global", async () => {
    const bin = await tempDir();
    await writeFile(join(bin, "dotation"), "#!/bin/sh\necho 0.0.0\n", { mode: 0o755 });
    const env = { PATH: `${bin}:${pathWithoutEngines()}`, HOME: await tempDir() } as NodeJS.ProcessEnv;
    expect(await mcpLaunch(env)).toEqual({ command: "dotation", args: ["mcp"] });
    const d = await tempDir();
    await mkdir(join(d, ".cursor"));
    await writeFile(join(d, ".cursor/mcp.json"), "{ // commentaire\n}");
    const [r] = await installAgent(d, { targets: ["cursor"], env });
    expect(r?.status).toBe("invalid");
    expect(await readFile(join(d, ".cursor/mcp.json"), "utf8")).toBe("{ // commentaire\n}");
    const g = await installAgent(d, { targets: ["claude", "agents"], global: true, env });
    expect(g.map((x) => x.path)).toEqual([
      join(env.HOME as string, ".claude/skills/dotation/SKILL.md"),
      join(env.HOME as string, ".agents/skills/dotation/SKILL.md"),
    ]);
    expect(() => parseTargets("claude,emacs")).toThrow("emacs");
  });

  it("par la ligne de commande", async () => {
    const d = await tempDir();
    const r = await cli(["agent", d], { PATH: pathWithoutEngines(), HOME: await tempDir() });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("created: .claude/skills/dotation/SKILL.md");
    expect(r.stdout).toContain("created: .mcp.json");
    expect((await cli(["agent", d, "--target", "emacs"])).code).toBe(2);
  });
});
