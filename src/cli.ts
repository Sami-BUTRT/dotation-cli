#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { lstat, mkdir, rename, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, InvalidArgumentError, Option } from "commander";
import { describeAgent, installAgent, mcpLaunch, parseTargets } from "./commands/agent.js";
import { cloudCommands, uploadReport } from "./commands/cloud.js";
import { describeInit, init } from "./commands/init.js";
import { BASELINE_PATH, serializeBaseline } from "./core/baseline.js";
import { atLeast, isSeverity, type Severity } from "./core/finding.js";
import { updateOsvDb } from "./engines/osv.js";
import { LANG_IGNORED_NOTICE, messages } from "./i18n/index.js";
import { startMcp } from "./mcp/server.js";
import { renderJson } from "./output/json.js";
import { renderPretty } from "./output/pretty.js";
import { renderSarif } from "./output/sarif.js";
import { collectComponents, toCycloneDx } from "./sbom/cyclonedx.js";
import { scan } from "./scan.js";
import { colorMode, localPlan, renderBanner, renderLogo, repoInfo, shouldShowBanner } from "./ui/banner.js";
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
  /** Legacy option: accepted, ignored. */
  lang?: string;
  all?: boolean;
  timeout?: number;
  color?: boolean;
  /** false avec --no-banner. */
  banner?: boolean;
  upload?: boolean;
  project?: string;
  hashPaths?: boolean;
  /** false avec --no-baseline ; chaîne avec --baseline <file>. */
  baseline?: boolean | string;
}

function severityArg(v: string): Severity {
  if (!isSeverity(v)) throw new InvalidArgumentError("low | medium | high | critical");
  return v;
}

/** Legacy language settings (--lang, DOTATION_LANG, `lang:` in .dotation.yml): accepted, ignored, one notice. */
function noteLegacyLang(flagLang: string | undefined, configIgnored: boolean | undefined): void {
  if (flagLang !== undefined || process.env.DOTATION_LANG?.trim() || configIgnored) {
    process.stderr.write(`${LANG_IGNORED_NOTICE}\n`);
  }
}

function intArg(v: string): number {
  const n = Number.parseInt(v, 10);
  if (!Number.isInteger(n) || n < 5 || n > 3600) throw new InvalidArgumentError("5 to 3600");
  return n;
}

function baselineOpt(flags: { baseline?: boolean | string }): { baseline?: false | string } {
  if (flags.baseline === false) return { baseline: false };
  return typeof flags.baseline === "string" ? { baseline: flags.baseline } : {};
}

/**
 * Écrit la baseline sans suivre de lien symbolique : le dépôt analysé est non fiable et pourrait faire de
 * .dotation ou de baseline.json un lien vers un fichier sensible. Temp créé en O_EXCL puis renommé.
 */
async function writeBaselineSafely(root: string, content: string): Promise<void> {
  const dir = join(realpathSync(root), dirname(BASELINE_PATH));
  const dirStat = await lstat(dir).catch(() => null);
  if (dirStat && !dirStat.isDirectory()) throw new Error("unsafe-path");
  if (!dirStat) await mkdir(dir);
  const file = join(dir, basename(BASELINE_PATH));
  const fileStat = await lstat(file).catch(() => null);
  if (fileStat && !fileStat.isFile()) throw new Error("unsafe-path");
  const tmp = join(dir, `.baseline.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
  try {
    await writeFile(tmp, content, { encoding: "utf8", flag: "wx" });
    await rename(tmp, file);
  } catch (e) {
    await unlink(tmp).catch(() => undefined);
    throw e;
  }
}

async function baselineCommand(path: string, flags: { lang?: string; allowPartial?: boolean }): Promise<number> {
  const m = messages();
  try {
    const report = await scan(path, { baseline: false, collectEntries: true });
    noteLegacyLang(flags.lang, report.langIgnored);
    const failed = report.statuses.filter((s) => s.state === "failed").map((s) => s.engine);
    if (failed.length > 0 && !flags.allowPartial) {
      process.stderr.write(`${m.cli.baselineIncomplete(failed.join(", "))}\n`);
      return EXIT_ERROR;
    }
    const entries = report.entries ?? [];
    await writeBaselineSafely(report.root, serializeBaseline(entries, VERSION));
    process.stdout.write(`${m.cli.baselineWritten(BASELINE_PATH, entries.length)}\n`);
    return EXIT_OK;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg === "unsafe-path") {
      process.stderr.write(`${m.cli.baselineUnsafe(BASELINE_PATH)}\n`);
      return EXIT_ERROR;
    }
    if (msg.startsWith("bad-path:")) process.stderr.write(`${m.cli.badPath(path)}\n`);
    else process.stderr.write(`dotation: ${msg}\n`);
    return EXIT_ERROR;
  }
}

/** En-tête (logo, version, projet, plan) : terminal interactif seulement, jamais d'appel réseau. */
async function printBanner(noBanner: boolean): Promise<boolean> {
  const env = process.env;
  const isTTY = process.stdout.isTTY === true;
  if (!shouldShowBanner({ isTTY, env, noBanner: noBanner || process.argv.includes("--no-banner") })) return false;
  const { repo, branch } = await repoInfo(process.cwd());
  process.stdout.write(
    renderBanner(
      {
        version: VERSION,
        repo,
        branch,
        plan: await localPlan(env),
        columns: process.stdout.columns ?? 80,
        color: colorMode(env),
      },
      messages(),
    ),
  );
  return true;
}

async function scanCommand(path: string, flags: ScanFlags): Promise<number> {
  const m = messages();
  let report: Awaited<ReturnType<typeof scan>>;
  try {
    report = await scan(path, {
      scope: flags.scope,
      staged: flags.staged ?? false,
      ...baselineOpt(flags),
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
  if (flags.format === "pretty") {
    noteLegacyLang(flags.lang, report.langIgnored);
    await printBanner(flags.banner === false);
  }
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

function helpBanner(): string {
  const env = process.env;
  if (!shouldShowBanner({ isTTY: process.stdout.isTTY === true, env, noBanner: process.argv.includes("--no-banner") }))
    return "";
  // L'aide est synchrone : logo et version seulement, sans lire dépôt ni identifiants.
  return `${renderLogo(colorMode(env)).join("\n")}\n\ndotation v${VERSION}\n\n`;
}

export function buildProgram(): Command {
  const h = messages();
  const m = h;
  const program = new Command()
    .name("dotation")
    .description(h.cli.description)
    .version(VERSION, "-v, --version")
    .option("--no-banner", "do not show the logo header (also DOTATION_NO_BANNER=1)")
    .showHelpAfterError()
    .addHelpText("beforeAll", () => helpBanner())
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
    .option("--lang <lang>", "deprecated, ignored: dotation is English-only")
    .option("--all", "show every finding (default: the 10 most severe)")
    .option("--timeout <seconds>", "time limit per engine (default: 60)", intArg)
    .option("--no-color", "no colors")
    .option("--no-banner", "do not show the logo header")
    .option("--baseline <file>", "use this baseline file (default: .dotation/baseline.json)")
    .option("--no-baseline", "show every finding, even those frozen by the baseline")
    .option("--upload", h.cloud.upload)
    .option("--project <name>", "project name for --upload (default: folder name)")
    .option("--hash-paths", "with --upload: send hashed file paths instead of paths")
    .action(async (path: string, flags: ScanFlags) => {
      process.exitCode = await scanCommand(path, flags);
    });

  program
    .command("baseline")
    .description(h.cli.baseline)
    .argument("[path]", "project root", ".")
    .option("--lang <lang>", "deprecated, ignored: dotation is English-only")
    .option("--allow-partial", "write the baseline even if an engine failed (it will be incomplete)")
    .action(async (path: string, flags: { lang?: string; allowPartial?: boolean }) => {
      process.exitCode = await baselineCommand(path, flags);
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

  program
    .command("sbom")
    .description(h.cli.sbom)
    .argument("[path]", "project root", ".")
    .option("-o, --output <file>", "write to this file instead of the standard output")
    .action(async (path: string, flags: { output?: string }) => {
      const root = resolve(path);
      const components = await collectComponents(root);
      const json = `${JSON.stringify(toCycloneDx(basename(root), components), null, 2)}\n`;
      if (!flags.output) {
        process.stdout.write(json);
        return;
      }
      await writeFile(resolve(flags.output), json, "utf8");
      process.stderr.write(`${m.cli.sbomWritten(flags.output, components.length)}\n`);
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
