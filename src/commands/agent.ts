// « dotation agent » : installe le skill dotation et déclare le serveur MCP pour les assistants de code.
// N'écrase rien sans --force ; fusionne les fichiers de configuration MCP existants sans toucher aux autres serveurs.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative } from "node:path";
import { hasCommand } from "../core/exec.js";
import { PINNED_TARBALL } from "../distribution.js";
import type { Messages } from "../i18n/index.js";
import { packagePath } from "../paths.js";

export const AGENT_TARGETS = ["claude", "agents", "cursor", "vscode"] as const;
export type AgentTarget = (typeof AGENT_TARGETS)[number];

export interface AgentResult {
  path: string;
  status: "created" | "updated" | "skipped" | "invalid";
}

/** Commande qui lance le serveur MCP : « dotation » s'il est installé, sinon le paquet de cette version via npx. */
export async function mcpLaunch(env: NodeJS.ProcessEnv = process.env): Promise<{ command: string; args: string[] }> {
  if (await hasCommand("dotation", ["--version"], env)) return { command: "dotation", args: ["mcp"] };
  return { command: "npx", args: ["--yes", `--package=${PINNED_TARBALL}`, "dotation", "mcp"] };
}

async function writeSkill(dir: string, force: boolean): Promise<AgentResult> {
  const path = join(dir, "dotation", "SKILL.md");
  const content = await readFile(packagePath("skills/dotation/SKILL.md"), "utf8");
  const current = await readFile(path, "utf8").catch(() => null);
  if (current === content) return { path, status: "skipped" };
  if (current !== null && !force) return { path, status: "skipped" };
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, "utf8");
  return { path, status: current === null ? "created" : "updated" };
}

/** Ajoute le serveur « dotation » sous `key` (mcpServers ou servers) d'un fichier JSON, sans toucher au reste. */
async function mergeMcp(
  path: string,
  key: "mcpServers" | "servers",
  entry: Record<string, unknown>,
  force: boolean,
): Promise<AgentResult> {
  const raw = await readFile(path, "utf8").catch(() => null);
  let doc: Record<string, unknown> = {};
  if (raw !== null && raw.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { path, status: "invalid" };
      doc = parsed as Record<string, unknown>;
    } catch {
      // Fichier illisible (JSON avec commentaires…) : on ne le réécrit pas, on dit quoi ajouter.
      return { path, status: "invalid" };
    }
  }
  const servers = (doc[key] ?? {}) as Record<string, unknown>;
  if (typeof servers !== "object" || Array.isArray(servers)) return { path, status: "invalid" };
  if (servers.dotation !== undefined && !force) return { path, status: "skipped" };
  doc[key] = { ...servers, dotation: entry };
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
  return { path, status: raw === null ? "created" : "updated" };
}

export interface AgentOptions {
  targets: readonly AgentTarget[];
  force?: boolean;
  /** Skills dans le dossier personnel (tous les projets) plutôt que dans le projet. */
  global?: boolean;
  env?: NodeJS.ProcessEnv;
}

export async function installAgent(root: string, opts: AgentOptions): Promise<AgentResult[]> {
  const force = opts.force ?? false;
  const home = opts.env?.HOME ?? homedir();
  const base = opts.global ? home : root;
  const launch = await mcpLaunch(opts.env);
  const out: AgentResult[] = [];
  for (const t of opts.targets) {
    if (t === "claude") {
      out.push(await writeSkill(join(base, ".claude", "skills"), force));
      // MCP de Claude Code au niveau utilisateur : sa propre commande (« claude mcp add -s user »), pas un fichier à nous.
      if (!opts.global) out.push(await mergeMcp(join(root, ".mcp.json"), "mcpServers", { ...launch }, force));
    } else if (t === "agents") {
      out.push(await writeSkill(join(base, ".agents", "skills"), force));
    } else if (t === "cursor") {
      out.push(await mergeMcp(join(base, ".cursor", "mcp.json"), "mcpServers", { ...launch }, force));
    } else if (t === "vscode" && !opts.global) {
      out.push(await mergeMcp(join(root, ".vscode", "mcp.json"), "servers", { type: "stdio", ...launch }, force));
    }
  }
  return out;
}

export function describeAgent(
  results: AgentResult[],
  root: string,
  launch: { command: string; args: string[] },
  global: boolean,
  m: Messages,
): string {
  const lines = results.map((r) => {
    const p = r.path.startsWith(`${root}/`) ? relative(root, r.path) : r.path;
    if (r.status === "created") return `✓ ${m.cli.initWrote(p)}`;
    if (r.status === "updated") return `✓ ${m.agent.updated(p)}`;
    if (r.status === "skipped") return `· ${m.cli.initSkipped(p)}`;
    return `! ${m.agent.invalid(p, JSON.stringify({ dotation: launch }))}`;
  });
  if (global) lines.push("", m.agent.userMcp([launch.command, ...launch.args].join(" ")));
  lines.push("", m.agent.next);
  return `${lines.join("\n")}\n`;
}

export function parseTargets(v: string): AgentTarget[] {
  const parts = v
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (parts.includes("all")) return [...AGENT_TARGETS];
  for (const p of parts) if (!(AGENT_TARGETS as readonly string[]).includes(p)) throw new Error(p);
  return [...new Set(parts)] as AgentTarget[];
}
