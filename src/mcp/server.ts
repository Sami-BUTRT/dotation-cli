import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { atLeast, type Finding } from "../core/finding.js";
import { gitleaksEngine } from "../engines/gitleaks.js";
import { houseEngine } from "../engines/house.js";
import { semgrepEngine } from "../engines/semgrep.js";
import { detectLang, isLang, type Lang, pick } from "../i18n/index.js";
import { loadRules } from "../rules/loader.js";
import { type ScanReport, scan } from "../scan.js";
import { VERSION } from "../version.js";

// Serveur MCP (stdio) : permet à Claude Code, Cursor, Codex… de vérifier le code qu'ils écrivent avant de le proposer.
// Tout reste local (aucun outil n'utilise le réseau) et les résultats sont ceux du rapport : secrets déjà masqués.

const MAX_FINDINGS = 50;
const MAX_FILES = 50;

/** Ce que l'agent lit à la connexion : quand appeler quel outil, et les règles à respecter. */
export const INSTRUCTIONS = `dotation finds basic security slip-ups (hardcoded secrets, committed .env files, open CORS, Supabase tables without RLS, open Firebase rules, injections, vulnerable dependencies, hidden code in starters). Everything runs locally; nothing leaves the machine.

When to use it:
- After writing or editing code that touches secrets, auth, database access, CORS, uploads or config: call scan_files on the files you changed.
- Before proposing a commit: call scan_staged on the repository. Before a deploy or release: call scan_project.
- To explain a finding to the user: call explain_rule with its id.

How to act on results:
- Fix critical and high findings first; tell the user plainly what was wrong and what you changed.
- Never print, copy or move a secret value. Snippets are already redacted; keep them that way.
- A leaked key must be revoked and replaced by the user at the provider: moving it to an environment variable is not enough. Say so.
- Do not silence a finding (dotation-ignore comment, disable in .dotation.yml) unless the user confirms it is intended.
- Re-scan after fixing to confirm.`;

export function summarize(report: ScanReport, limit = MAX_FINDINGS) {
  const findings = report.findings.slice(0, limit).map((f: Finding) => ({
    id: f.id,
    severity: f.severity,
    category: f.category,
    title: f.title,
    file: f.file,
    line: f.line,
    explanation: f.explanation,
    fix: f.fix,
    snippet: f.snippet,
  }));
  return {
    score: report.score,
    total: report.findings.length,
    blocking: report.findings.filter((f) => atLeast(f.severity, "high")).length,
    findings,
    truncated: report.findings.length > limit,
    engines: report.statuses.map((s) => ({ engine: s.engine, state: s.state })),
  };
}

const langArg = z
  .enum(["en", "fr", "es", "zh"])
  .optional()
  .describe("Language of titles and explanations (default: en)");
const asText = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v, null, 2) }] });
const asError = (v: unknown) => ({ ...asText(v), isError: true });
// Lecture seule, sans réseau : l'agent peut appeler ces outils sans risque.
const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

function failure(e: unknown, path: string) {
  const msg = e instanceof Error ? e.message : String(e);
  if (msg.startsWith("bad-path:")) return asError({ error: `path not found: ${path}` });
  if (msg === "not-a-git-repo") return asError({ error: `not a git repository: ${path}` });
  return asError({ error: msg });
}

export function createServer(defaultLang: Lang = detectLang()): McpServer {
  const server = new McpServer({ name: "dotation", version: VERSION }, { instructions: INSTRUCTIONS });
  const langOf = (l: string | undefined): Lang => (l && isLang(l) ? l : defaultLang);

  server.registerTool(
    "scan_project",
    {
      title: "Scan a project",
      description:
        "Scan a whole project or folder for security slip-ups: hardcoded secrets, committed sensitive files, open CORS, Supabase without RLS, open Firebase rules, injections, vulnerable dependencies. Local only. Returns a 0-100 score and findings, most severe first, secrets redacted.",
      inputSchema: {
        path: z.string().describe("Absolute path of the project to scan"),
        lang: langArg,
        all: z.boolean().optional().describe(`Return up to 500 findings instead of ${MAX_FINDINGS}`),
      },
      annotations: readOnly,
    },
    async ({ path, lang, all }) => {
      try {
        return asText(summarize(await scan(path, { lang: langOf(lang) }), all ? 500 : MAX_FINDINGS));
      } catch (e) {
        return failure(e, path);
      }
    },
  );

  server.registerTool(
    "scan_staged",
    {
      title: "Scan staged changes",
      description:
        "Scan only the staged files (git add) of a repository, like the pre-commit hook. Use before proposing a commit.",
      inputSchema: { path: z.string().describe("Absolute path of the git repository"), lang: langArg },
      annotations: readOnly,
    },
    async ({ path, lang }) => {
      try {
        return asText(summarize(await scan(path, { staged: true, lang: langOf(lang) })));
      } catch (e) {
        return failure(e, path);
      }
    },
  );

  server.registerTool(
    "scan_files",
    {
      title: "Scan files you just changed",
      description: `Scan specific files (up to ${MAX_FILES}), for example the ones you just wrote or edited. Faster than a full scan: dependency checks are left out.`,
      inputSchema: {
        paths: z.array(z.string()).min(1).max(MAX_FILES).describe("Absolute paths of the files to scan"),
        lang: langArg,
      },
      annotations: readOnly,
    },
    async ({ paths, lang }) => {
      const findings: Finding[] = [];
      const missing: string[] = [];
      for (const p of paths) {
        try {
          const r = await scan(p, { lang: langOf(lang), engines: [houseEngine, gitleaksEngine, semgrepEngine] });
          findings.push(...r.findings.map((f) => ({ ...f, file: resolve(r.root, f.file) })));
        } catch {
          missing.push(p);
        }
      }
      const order = ["critical", "high", "medium", "low"];
      findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
      return asText({
        total: findings.length,
        blocking: findings.filter((f) => atLeast(f.severity, "high")).length,
        findings: summarize({ findings, statuses: [] } as unknown as ScanReport).findings,
        truncated: findings.length > MAX_FINDINGS,
        ...(missing.length ? { notFound: missing } : {}),
      });
    },
  );

  server.registerTool(
    "explain_rule",
    {
      title: "Explain a rule",
      description:
        "Explain a dotation rule (id such as DOT-SEC-001, shown in every finding): the risk and how to fix it.",
      inputSchema: { id: z.string().describe("Rule id, e.g. DOT-SEC-001"), lang: langArg },
      annotations: readOnly,
    },
    async ({ id, lang }) => {
      const rules = await loadRules([]);
      const rule = rules.find((r) => r.id === id.trim().toUpperCase());
      if (!rule) return asError({ error: `unknown rule: ${id}`, known: rules.map((r) => r.id) });
      const t = pick(rule.text, langOf(lang));
      return asText({ id: rule.id, severity: rule.severity, category: rule.category, ...t });
    },
  );

  server.registerTool(
    "list_rules",
    {
      title: "List rules",
      description: "List the built-in dotation rules (id, severity, category, title).",
      inputSchema: { lang: langArg },
      annotations: readOnly,
    },
    async ({ lang }) => {
      const rules = await loadRules([]);
      return asText(
        rules.map((r) => ({
          id: r.id,
          severity: r.severity,
          category: r.category,
          title: pick(r.text, langOf(lang))?.title,
        })),
      );
    },
  );
  return server;
}

export async function startMcp(): Promise<void> {
  await createServer().connect(new StdioServerTransport());
}
