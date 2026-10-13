#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, InvalidArgumentError, Option } from "commander";
import { describeAgent, installAgent, mcpLaunch, parseTargets } from "./commands/agent.js";
import { cloudCommands, uploadReport } from "./commands/cloud.js";
import { describeInit, init } from "./commands/init.js";
import { atLeast, isSeverity, type Severity } from "./core/finding.js";
import { updateOsvDb } from "./engines/osv.js";
import { detectLang, isLang, type Lang, messages } from "./i18n/index.js";
import { startMcp } from "./mcp/server.js";
import { renderJson } from "./output/json.js";
import { renderPretty } from "./output/pretty.js";
import { renderSarif } from "./output/sarif.js";
import { scan } from "./scan.js";
import { VERSION } from "./version.js";

// Codes retour : 0 = rien de bloquant, 1 = problème au niveau --fail-on ou plus, 2 = erreur d'utilisation.
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

interface ScanFlags {
  scope: "file" | "dir" | "project";
  staged?: boolean;
  format: "pretty" | "json" | "sarif";
  failOn?: Severity;
  lang?: Lang;
  all?: boolean;
  timeout?: number;
  color?: boolean;
  upload?: boolean;
  project?: string;
  hashPaths?: boolean;
}

function severityArg(v: string): Severity {
  if (!isSeverity(v)) throw new InvalidArgumentError("low | medium | high | critical");
  return v;
}

function langArg(v: string): Lang {
  const l = v.toLowerCase() === "cn" ? "zh" : v.toLowerCase();
  if (!isLang(l)) throw new InvalidArgumentError("fr | en | es | zh");
  return l;
}

function intArg(v: string): number {
  const n = Number.parseInt(v, 10);
  if (!Number.isInteger(n) || n < 5 || n > 3600) throw new InvalidArgumentError("5 to 3600");
  return n;
}

async function scanCommand(path: string, flags: ScanFlags): Promise<number> {
  const lang = flags.lang ?? detectLang();
  const m = messages(lang);
  let report: Awaited<ReturnType<typeof scan>>;
  try {
    report = await scan(path, {
      scope: flags.scope,
      staged: flags.staged ?? false,
      lang,
      ...(flags.timeout ? { timeoutSec: flags.timeout } : {}),
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.startsWith("bad-path:")) process.stderr.write(`${m.cli.badPath(path)}\n`);
    else if (msg === "not-a-git-repo") process.stderr.write(`${m.cli.notGit}\n`);
    else process.stderr.write(`dotation: ${msg}\n`);
    return EXIT_ERROR;
  }
  const failOn: Severity = flags.failOn ?? "high";
  const failed = report.findings.some((f) => atLeast(f.severity, failOn));
  if (flags.format === "json") process.stdout.write(renderJson(report));
  else if (flags.format === "sarif") process.stdout.write(renderSarif(report));
  else {
    const color = flags.color !== false && process.stdout.isTTY === true && !process.env.NO_COLOR;
    process.stdout.write(renderPretty(report, { all: flags.all ?? false, color, failOn, failed }));
  }
  // Envoi seulement sur demande explicite ; un échec d'envoi ne change pas le résultat du scan local.
  if (flags.upload) {
    await uploadReport(
      report,
      { ...(flags.project ? { project: flags.project } : {}), hashPaths: flags.hashPaths ?? false },
      m,
    );
  }
  return failed ? EXIT_FINDINGS : EXIT_OK;
}

export function buildProgram(): Command {
  // Aide et options toujours en anglais ; les messages d'exécution suivent la langue choisie.
  const h = messages("en");
  const m = messages(detectLang());
  const program = new Command()
    .name("dotation")
    .description(h.cli.description)
    .version(VERSION, "-v, --version")
    .showHelpAfterError()
    // Avant de déclarer les sous-commandes : commander leur copie ce réglage à leur création.
    .exitOverride((err) => {
      process.exit(err.exitCode === 0 ? 0 : EXIT_ERROR);
    });

  program
    .command("scan", { isDefault: true })
    .description(h.cli.scan)
    .argument("[path]", "project, folder or file", ".")
    .addOption(
      new Option("--scope <scope>", "file | dir | project").choices(["file", "dir", "project"]).default("project"),
    )
    .option("--staged", "only the staged files (git add)")
    .addOption(
      new Option("--format <format>", "pretty | json | sarif").choices(["pretty", "json", "sarif"]).default("pretty"),
    )
    .option("--fail-on <severity>", "exit code 1 from this severity up (default: high)", severityArg)
    .option("--lang <lang>", "report language: en | fr | es | zh (default: en, or DOTATION_LANG)", langArg)
    .option("--all", "show every finding (default: the 10 most severe)")
    .option("--timeout <seconds>", "time limit per engine (default: 60)", intArg)
    .option("--no-color", "no colors")
    .option("--upload", h.cloud.upload)
    .option("--project <name>", "project name for --upload (default: folder name)")
    .option("--hash-paths", "with --upload: send hashed file paths instead of paths")
    .action(async (path: string, flags: ScanFlags) => {
      process.exitCode = await scanCommand(path, flags);
    });

  program
    .command("init")
    .description(h.cli.init)
    .argument("[path]", "project root", ".")
    .option("--force", "overwrite existing files")
    .action(async (path: string, flags: { force?: boolean }) => {
      const root = resolve(path);
      process.stdout.write(describeInit(await init(root, flags.force ?? false), root, m));
    });

  program
    .command("agent")
    .description(h.cli.agent)
    .argument("[path]", "project root", ".")
    .option(
      "--target <list>",
      "claude, agents (.agents/skills: Codex and others), cursor, vscode, or all",
      "claude,agents",
    )
    .option("--global", "install the skills in your home folder, for every project")
    .option("--force", "overwrite existing files")
    .action(async (path: string, flags: { target: string; global?: boolean; force?: boolean }) => {
      let targets: ReturnType<typeof parseTargets>;
      try {
        targets = parseTargets(flags.target);
      } catch (e) {
        process.stderr.write(`${m.agent.badTarget((e as Error).message)}\n`);
        process.exitCode = EXIT_ERROR;
        return;
      }
      const root = resolve(path);
      const global = flags.global ?? false;
      const results = await installAgent(root, { targets, global, force: flags.force ?? false });
      process.stdout.write(describeAgent(results, root, await mcpLaunch(), global && targets.includes("claude"), m));
    });

  program
    .command("mcp")
    .description(h.cli.mcp)
    .action(async () => {
      await startMcp();
    });

  program
    .command("update-db")
    .description(h.cli.updateDb)
    .argument("[path]", "project whose ecosystems are downloaded (npm, PyPI…)", ".")
    .action(async (path: string) => {
      const r = await updateOsvDb(resolve(path));
      if (r.ok) process.stdout.write(`${m.cli.updateDbDone}\n`);
      else {
        process.stderr.write(`dotation update-db: ${r.error ?? ""}\n`);
        process.exitCode = EXIT_ERROR;
      }
    });

  cloudCommands(program, m, h);
  return program;
}

// Lancé directement (node dist/cli.js) ou par le lien bin/dotation d'une installation npm : on compare les chemins réels.
const isMain = (() => {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();
if (isMain) {
  // Lecteur qui ferme la sortie avant la fin (dotation … | head -1) : on s'arrête proprement, sans trace d'erreur.
  for (const stream of [process.stdout, process.stderr]) {
    stream.on("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "EPIPE") process.exit(process.exitCode ?? 0);
      throw e;
    });
  }
  buildProgram()
    .parseAsync(process.argv)
    .catch((e: unknown) => {
      process.stderr.write(`dotation: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(EXIT_ERROR);
    });
}
