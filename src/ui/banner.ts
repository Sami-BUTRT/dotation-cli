import { open, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { loadCredentials } from "../cloud/config.js";
import { safeLine } from "../core/terminal.js";
import type { Messages } from "../i18n/index.js";
import { cells, INK, RED } from "./logo-grid.js";

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
const RED_SEQ: Record<Exclude<ColorMode, "none">, string> = { truecolor: "\x1b[38;2;232;50;14m", ansi: "\x1b[31m" };
const NARROW = 50;

/** Logo en demi-blocs : 2 rangées de pixels par ligne de terminal. Le « noir » reste en couleur d'avant-plan par défaut. */
export function renderLogo(color: ColorMode): string[] {
  const grid = new Map<string, "r" | "k">();
  for (const c of [...cells(RED, "r"), ...cells(INK, "k")]) grid.set(`${c.x},${c.y}`, c.c);
  const w = Math.max(...[...grid.keys()].map((k) => Number(k.split(",")[0]))) + 1;
  const h = Math.max(...[...grid.keys()].map((k) => Number(k.split(",")[1]))) + 1;
  const lines: string[] = [];
  for (let y = 0; y < h; y += 2) {
    let line = "";
    for (let x = 0; x < w; x++) {
      const top = grid.get(`${x},${y}`);
      const bot = grid.get(`${x},${y + 1}`);
      const ch = top && bot ? "█" : top ? "▀" : bot ? "▄" : " ";
      const kind = top ?? bot;
      line += kind === "r" && color !== "none" ? `${RED_SEQ[color]}${ch}${RESET}` : ch;
    }
    lines.push(line.trimEnd());
  }
  return lines;
}

export function renderBanner(info: BannerInfo, m: Messages): string {
  const repo = safeLine(info.repo);
  const where = info.branch ? `${repo} (${safeLine(info.branch)})` : repo;
  const plan =
    info.plan === "pro" ? m.banner.planPro : info.plan === "pro?" ? m.banner.planProUnknown : m.banner.planFree;
  if (info.columns < NARROW) return `dotation v${info.version} — ${where} — ${plan}\n`;
  const word = "D O T A T I O N . A P P";
  return `${[
    ...renderLogo(info.color),
    word.padStart(Math.floor((40 + word.length) / 2)),
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
