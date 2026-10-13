import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative } from "node:path";
import { CONFIG_FILE } from "../core/config.js";
import { run } from "../core/exec.js";
import { gitToplevel } from "../core/files.js";
import { installCommand, PINNED_TARBALL } from "../distribution.js";
import type { Messages } from "../i18n/index.js";

export const CONFIG_TEMPLATE = `# dotation settings (https://www.dotation.app). Everything is optional.
# Severity from which "dotation scan" exits with code 1: low | medium | high | critical
failOn: high
# Folders or files to skip, on top of node_modules, dist, build, .next…
exclude: []
#  - "legacy/**"
# Rules to turn off (id shown in the JSON or SARIF report)
disable: []
#  - DOT-CFG-004
engines:
  gitleaks: true
  semgrep: true
  osv: true
# Time limit per engine, in seconds
timeout: 60
# Report language: en | fr | es | zh
# lang: en
`;

export const HOOK_MARKER = "# dotation pre-commit";
export const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}
# Blocks the commit when a staged change has a high (or worse) problem. Skip once: git commit --no-verify
if ! command -v dotation >/dev/null 2>&1; then
  echo "dotation is not installed: commit not checked. Install it with: ${installCommand()}" >&2
  exit 0
fi
exec dotation scan --staged --fail-on high
`;

export const WORKFLOW = `# dotation scan on every push and pull request; results show up in the Security tab (Code scanning).
name: dotation

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Install dotation
        run: npm install -g ${PINNED_TARBALL}
      - name: dotation
        run: dotation scan --format sarif --fail-on high > dotation.sarif
      - name: Upload results to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: dotation.sarif
          category: dotation
`;

export interface InitResult {
  path: string;
  status: "created" | "skipped" | "hook-exists";
}

async function exists(p: string): Promise<boolean> {
  return access(p).then(
    () => true,
    () => false,
  );
}

async function writeNew(path: string, content: string, force: boolean, mode?: number): Promise<"created" | "skipped"> {
  if (!force && (await exists(path))) return "skipped";
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, { encoding: "utf8", ...(mode ? { mode } : {}) });
  if (mode) await chmod(path, mode);
  return "created";
}

/** Dossier des hooks git (core.hooksPath ou .git/hooks), ou .husky si le projet utilise Husky. */
async function hookPath(gitRoot: string): Promise<string> {
  if (await exists(join(gitRoot, ".husky"))) return join(gitRoot, ".husky", "pre-commit");
  const r = await run("git", ["rev-parse", "--git-path", "hooks"], { cwd: gitRoot, timeoutMs: 10_000 });
  const dir = r.code === 0 ? r.stdout.trim() : ".git/hooks";
  return join(isAbsolute(dir) ? dir : join(gitRoot, dir), "pre-commit");
}

export async function init(root: string, force: boolean): Promise<InitResult[]> {
  const out: InitResult[] = [];
  out.push({ path: join(root, CONFIG_FILE), status: await writeNew(join(root, CONFIG_FILE), CONFIG_TEMPLATE, force) });

  const gitRoot = await gitToplevel(root);
  const wf = join(gitRoot ?? root, ".github", "workflows", "dotation.yml");
  out.push({ path: wf, status: await writeNew(wf, WORKFLOW, force) });

  if (gitRoot) {
    const hook = await hookPath(gitRoot);
    const current = await readFile(hook, "utf8").catch(() => null);
    if (current !== null && !current.includes(HOOK_MARKER) && !force) out.push({ path: hook, status: "hook-exists" });
    else if (current?.includes(HOOK_MARKER) && !force) out.push({ path: hook, status: "skipped" });
    else out.push({ path: hook, status: await writeNew(hook, HOOK_SCRIPT, true, 0o755) });
  }
  return out;
}

export function describeInit(results: InitResult[], root: string, m: Messages): string {
  return `${results
    .map((r) => {
      const p = relative(root, r.path) || r.path;
      if (r.status === "created") return `✓ ${m.cli.initWrote(p)}`;
      if (r.status === "skipped") return `· ${m.cli.initSkipped(p)}`;
      return `! ${m.cli.initHookExists(p)}`;
    })
    .join("\n")}\n`;
}
