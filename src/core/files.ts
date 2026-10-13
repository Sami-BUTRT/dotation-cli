import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { run } from "./exec.js";
import { matchAny } from "./glob.js";

export type Scope = "file" | "dir" | "project";

export const MAX_FILE_BYTES = 1024 * 1024;

/** Dossiers jamais parcourus (dépendances, builds, caches). */
export const DEFAULT_EXCLUDES: readonly string[] = [
  "**/node_modules/**",
  "**/.git/**",
  "**/.next/**",
  "**/dist/**",
  "**/build/**",
  "**/out/**",
  "**/coverage/**",
  "**/.venv/**",
  "**/venv/**",
  "**/__pycache__/**",
  "**/.turbo/**",
  "**/.vercel/**",
  "**/vendor/**",
];

export interface ScanFile {
  /** Relatif à la racine du scan, « / ». */
  path: string;
  read(): Promise<string | null>;
}

export interface FileSet {
  root: string;
  files: ScanFile[];
  /** Dépôt git contenant la racine (ou null). */
  gitRoot: string | null;
  /** Fichiers suivis par git (chemins relatifs à `root`), null hors dépôt. */
  tracked: Set<string> | null;
}

const toPosix = (p: string) => p.split(sep).join("/");

/** .env, .env.local, .env.production… (pas les modèles .env.example / .env.sample / .env.template). */
export function isEnvFile(path: string): boolean {
  const name = path.split("/").pop() ?? path;
  return /^\.env(\..+)?$/.test(name) && !/\.(example|sample|template|dist|defaults?)$/.test(name);
}

export async function gitToplevel(dir: string): Promise<string | null> {
  const r = await run("git", ["rev-parse", "--show-toplevel"], { cwd: dir, timeoutMs: 10_000 });
  return r.code === 0 ? r.stdout.trim() : null;
}

/** Contenu texte d'un fichier, ou null s'il est trop gros, binaire ou illisible. */
export async function readText(abs: string): Promise<string | null> {
  try {
    const s = await stat(abs);
    if (!s.isFile() || s.size > MAX_FILE_BYTES) return null;
    const buf = await readFile(abs);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

async function walk(root: string, dir: string, recursive: boolean, excludes: readonly string[], out: string[]) {
  let entries: import("node:fs").Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const abs = join(dir, e.name);
    const rel = toPosix(relative(root, abs));
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (recursive && !matchAny(`${rel}/`, excludes) && !matchAny(`${rel}/x`, excludes)) {
        await walk(root, abs, recursive, excludes, out);
      }
    } else if (e.isFile() && !matchAny(rel, excludes)) out.push(rel);
  }
}

async function gitList(gitRoot: string, root: string, args: string[]): Promise<string[] | null> {
  const r = await run(
    "git",
    ["-c", "core.quotepath=off", ...args, "-z", "--", toPosix(relative(gitRoot, root)) || "."],
    {
      cwd: gitRoot,
      timeoutMs: 30_000,
    },
  );
  if (r.code !== 0) return null;
  return r.stdout
    .split("\0")
    .filter(Boolean)
    .map((p) => toPosix(relative(root, join(gitRoot, p))));
}

export interface CollectOptions {
  scope: Scope;
  staged: boolean;
  excludes: readonly string[];
}

/**
 * Liste les fichiers à analyser.
 * - project : tout le dossier, récursivement (fichiers ignorés par git exclus si c'est un dépôt) ;
 * - dir : seulement les fichiers du dossier, sans descendre ;
 * - file : le fichier donné ;
 * - staged : seulement les fichiers indexés (git add), lus depuis l'index et non depuis le disque.
 */
export async function collectFiles(target: string, opts: CollectOptions): Promise<FileSet> {
  const s = await stat(target);
  const isFile = s.isFile();
  const root = isFile ? join(target, "..") : target;
  const gitRoot = await gitToplevel(root);
  const excludes = [...DEFAULT_EXCLUDES, ...opts.excludes];

  let tracked: Set<string> | null = null;
  if (gitRoot) {
    const t = await gitList(gitRoot, root, ["ls-files", "--cached"]);
    if (t) tracked = new Set(t);
  }

  if (opts.staged) {
    if (!gitRoot) throw new Error("not-a-git-repo");
    const r = await run(
      "git",
      ["-c", "core.quotepath=off", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
      {
        cwd: gitRoot,
        timeoutMs: 30_000,
      },
    );
    const staged = r.stdout.split("\0").filter(Boolean);
    const files: ScanFile[] = [];
    for (const p of staged) {
      const rel = toPosix(relative(root, join(gitRoot, p)));
      if (rel.startsWith("..") || matchAny(rel, excludes)) continue;
      files.push({ path: rel, read: () => readIndex(gitRoot, p) });
    }
    return { root, files, gitRoot, tracked: tracked ?? new Set(staged) };
  }

  let paths: string[];
  if (isFile) {
    paths = [toPosix(relative(root, target))];
  } else if (gitRoot && opts.scope === "project") {
    const listed = await gitList(gitRoot, root, ["ls-files", "--cached", "--others", "--exclude-standard"]);
    // Les .env ignorés par git (bonne pratique) sont lus quand même : une variable NEXT_PUBLIC_* secrète y reste un problème.
    const ignored = await gitList(gitRoot, root, ["ls-files", "--others", "--ignored", "--exclude-standard"]);
    const envs = (ignored ?? []).filter((p) => isEnvFile(p));
    paths = [...(listed ?? []), ...envs].filter((p) => !matchAny(p, excludes));
  } else {
    paths = [];
    await walk(root, root, opts.scope !== "dir", excludes, paths);
  }
  const unique = [...new Set(paths)].sort();
  return {
    root,
    gitRoot,
    tracked,
    files: unique.map((p) => ({ path: p, read: () => readText(join(root, p)) })),
  };
}

async function readIndex(gitRoot: string, p: string): Promise<string | null> {
  const r = await run("git", ["show", `:${p}`], { cwd: gitRoot, timeoutMs: 15_000, maxBuffer: MAX_FILE_BYTES * 2 });
  if (r.code !== 0 || r.stdout.length > MAX_FILE_BYTES || r.stdout.includes("\0")) return null;
  return r.stdout;
}
