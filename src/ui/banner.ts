import { open, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { loadCredentials } from "../cloud/config.js";
import { safeLine } from "../core/terminal.js";
import type { Messages } from "../i18n/index.js";
import { type Ink, symbolGrid } from "./symbol.js";

export type Plan = "free" | "pro" | "pro?";
export type ColorMode = "none" | "ansi" | "truecolor";

export interface BannerInfo {
  version: string;
  repo: string;
  branch?: string | undefined;
  plan: Plan;
  columns: number;
  color: ColorMode;
}

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const BOLD_OFF = "\x1b[22m";
/** Couleurs de la charte : ciel #8DCFF5, abricot #FF9A62 ; en 16 couleurs, cyan clair et jaune (souvent orangé). */
const FG: Record<Exclude<ColorMode, "none">, Record<Ink, string>> = {
  truecolor: { sky: "\x1b[38;2;141;207;245m", apricot: "\x1b[38;2;255;154;98m" },
  ansi: { sky: "\x1b[96m", apricot: "\x1b[33m" },
};
const BG: Record<Exclude<ColorMode, "none">, Record<Ink, string>> = {
  truecolor: { sky: "\x1b[48;2;141;207;245m", apricot: "\x1b[48;2;255;154;98m" },
  ansi: { sky: "\x1b[106m", apricot: "\x1b[43m" },
};
const NARROW = 50;

/** Symbole « Le saut » en demi-blocs (2 pixels par ligne de terminal), puis le mot « dotation » en gras à droite. */
export function renderLogo(color: ColorMode): string[] {
  const grid = symbolGrid(24, 16);
  const lines: string[] = [];
  for (let y = 0; y < grid.length; y += 2) {
    let line = "";
    const top = grid[y] ?? [];
    const bot = grid[y + 1] ?? [];
    for (let x = 0; x < top.length; x++) {
      const t = top[x];
      const b = bot[x];
      if (!t && !b) {
        line += " ";
        continue;
      }
      const ch = t && b && t === b ? "█" : t ? "▀" : "▄";
      if (color === "none") line += t && b ? (t === b ? "█" : "▀") : ch;
      else if (t && b && t !== b) line += `${FG[color][t]}${BG[color][b]}▀${RESET}`;
      else line += `${FG[color][(t ?? b) as Ink]}${ch}${RESET}`;
    }
    lines.push(line.trimEnd());
  }
  // Mot-symbole à droite, sur la ligne la plus large (milieu du symbole), comme le logo du site.
  const row = Math.min(lines.length - 1, 4);
  const word = color === "none" ? "dotation" : `${BOLD}dotation${BOLD_OFF}`;
  const width = 24;
  const plain = (s: string) => s.replace(new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g"), "");
  lines[row] = `${lines[row] ?? ""}${" ".repeat(Math.max(1, width + 2 - [...plain(lines[row] ?? "")].length))}${word}`;
  return lines;
}

export function renderBanner(info: BannerInfo, m: Messages): string {
  const repo = safeLine(info.repo);
  const where = info.branch ? `${repo} (${safeLine(info.branch)})` : repo;
  const plan =
    info.plan === "pro" ? m.banner.planPro : info.plan === "pro?" ? m.banner.planProUnknown : m.banner.planFree;
  if (info.columns < NARROW) return `dotation v${info.version} — ${where} — ${plan}\n`;
  return `${[
    ...renderLogo(info.color),
    "",
    `dotation v${info.version}`,
    `${m.banner.project} ${where}`,
    `${m.banner.plan} ${plan}`,
  ].join("\n")}\n\n`;
}

export function colorMode(env: NodeJS.ProcessEnv): ColorMode {
  if (env.NO_COLOR) return "none";
  return env.COLORTERM === "truecolor" || env.COLORTERM === "24bit" ? "truecolor" : "ansi";
}

function ciSet(v: string | undefined): boolean {
  const t = (v ?? "").trim().toLowerCase();
  return t !== "" && t !== "0" && t !== "false";
}

export function shouldShowBanner(o: {
  isTTY: boolean;
  env: NodeJS.ProcessEnv;
  noBanner?: boolean | undefined;
  quiet?: boolean | undefined;
  format?: string | undefined;
}): boolean {
  if (!o.isTTY || o.noBanner || o.quiet) return false;
  if (o.format && o.format !== "pretty") return false;
  if (o.env.DOTATION_NO_BANNER === "1" || ciSet(o.env.CI)) return false;
  return true;
}

/** Plan connu localement seulement (jamais d'appel réseau) : en cache dans les identifiants, sinon honnête. */
export async function localPlan(env: NodeJS.ProcessEnv = process.env): Promise<Plan> {
  try {
    const c = await loadCredentials(env);
    if (!c) return "free";
    if (c.plan === "free") return "free";
    return c.plan === "pro" ? "pro" : "pro?";
  } catch {
    return "free";
  }
}

async function exists(p: string): Promise<boolean> {
  return stat(p).then(
    () => true,
    () => false,
  );
}

function inside(parent: string, p: string): boolean {
  return p === parent || p.startsWith(parent.endsWith(sep) ? parent : parent + sep);
}

function gitDirAllowed(repoDir: string, target: string): boolean {
  if (inside(repoDir, target)) return true;
  for (let a = dirname(repoDir); ; a = dirname(a)) {
    if (inside(join(a, ".git", "worktrees"), target) && target !== join(a, ".git", "worktrees")) return true;
    if (dirname(a) === a) return false;
  }
}

async function readHead(p: string): Promise<string> {
  try {
    const fh = await open(p, "r");
    try {
      const buf = Buffer.alloc(512);
      const { bytesRead } = await fh.read(buf, 0, 512, 0);
      return buf.toString("utf8", 0, bytesRead);
    } finally {
      await fh.close();
    }
  } catch {
    return "";
  }
}

/** Dossier du dépôt (nom seul) et branche, lus dans .git sans lancer git. Hors dépôt : nom du dossier courant. */
export async function repoInfo(cwd: string): Promise<{ repo: string; branch?: string }> {
  let dir = resolve(cwd);
  for (;;) {
    const dotGit = join(dir, ".git");
    if (await exists(dotGit)) {
      let gitDir = dotGit;
      try {
        const txt = await readFile(dotGit, "utf8"); // fichier : worktree ou sous-module
        const m = /^gitdir:\s*(.+)$/m.exec(txt);
        if (m?.[1]) {
          const target = resolve(dir, m[1].trim());
          // .git non fiable : la cible doit être dans le dépôt ou dans .git/worktrees/* d'un dossier parent
          if (gitDirAllowed(dir, target)) gitDir = target;
          else gitDir = "";
        }
      } catch {
        /* c'est un dossier */
      }
      const head = gitDir ? await readHead(join(gitDir, "HEAD")) : "";
      const ref = /^ref:\s*refs\/heads\/(.+)$/m.exec(head);
      const branch = ref?.[1]?.trim() ?? (/^[0-9a-f]{7,}/.test(head) ? head.slice(0, 7) : undefined);
      return { repo: basename(dir), ...(branch ? { branch } : {}) };
    }
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return { repo: basename(resolve(cwd)) || "." };
}
