import type { Dirent } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { loadConfig } from "../core/config.js";
import { collectFiles, DEFAULT_EXCLUDES, readText, type ScanFile } from "../core/files.js";
import { matchAny } from "../core/glob.js";
import { detect } from "../rules/detectors.js";
import { loadRuleSet } from "../rules/loader.js";
import { type Engine, result } from "./engine.js";

/** Règles maison (YAML) : toujours disponibles, aucun outil externe. */
export const houseEngine: Engine = {
  id: "house",
  async scan(ctx) {
    const { rules, fromProject, overridden, protectedRejected, skipped } = await loadRuleSet(
      ctx.extraRuleDirs,
      ctx.projectRuleDir,
    );
    const cache = new Map<string, Promise<string | null>>();
    const byPath = new Map(ctx.fileSet.files.map((f) => [f.path, f]));
    const content = (path: string) => {
      let p = cache.get(path);
      if (!p) {
        p = byPath.get(path)?.read() ?? Promise.resolve(null);
        cache.set(path, p);
      }
      return p;
    };
    // Fichier seul, indexé ou sous-dossier : les conditions `when` portent sur tout le projet, pas sur le sous-ensemble.
    let projectFiles: (() => Promise<ScanFile[]>) | undefined;
    let projectTooLarge = false;
    const top = await projectRoot(ctx.fileSet.root, ctx.fileSet.gitRoot);
    if (ctx.staged || ctx.scope !== "project" || top !== ctx.fileSet.root) {
      let listing: Promise<ScanFile[]> | undefined;
      projectFiles = () => {
        listing ??= listProject(top, ctx.fileSet.gitRoot, ctx.config.exclude).then((fs) => {
          if (fs) return fs;
          // Trop gros : on abandonne la liste du projet, les conditions portent sur les fichiers scannés seulement.
          projectTooLarge = true;
          return ctx.fileSet.files;
        });
        return listing;
      };
    }
    const findings = (
      await Promise.all(
        rules.map((r) =>
          detect(r, {
            fileSet: ctx.fileSet,
            scope: ctx.staged ? "file" : ctx.scope,
            content,
            ...(projectFiles ? { projectFiles } : {}),
          }),
        ),
      )
    ).flat();
    // Les conditions sont évaluées paresseusement : le drapeau n'est connu qu'après les détecteurs.
    for (const f of findings) if (fromProject.has(f.id)) f.projectRule = true;
    return {
      ...result("house", "ok", findings),
      ruleNotices: {
        overridden,
        protectedRejected,
        skippedFiles: skipped,
        ...(projectTooLarge ? { projectTooLarge } : {}),
      },
    };
  },
};

const MARKERS = [".git", "package.json", "supabase", ".dotation.yml", "pyproject.toml", "go.mod"];

/** Plafonds de la liste du projet (modifiables par les tests). */
export const houseLimits = { maxProjectFiles: 20_000 };

/** Dossiers cachés parcourus dans la liste du projet (les autres, ~/.ssh, ~/.config…, sont ignorés). */
const HIDDEN_DIRS_ALLOWED = new Set([".github", ".dotation"]);

/** Dossier interdit comme racine de projet : $HOME, ses parents et la racine du disque. */
function forbiddenRoot(dir: string, home: string): boolean {
  const d = resolve(dir);
  const h = resolve(home);
  return dirname(d) === d || d === h || h.startsWith(d.endsWith(sep) ? d : d + sep);
}

/**
 * Racine du projet : dépôt git s'il y en a un, sinon le plus proche dossier parent portant un marqueur (au plus 8 niveaux).
 * Ne remonte jamais jusqu'à $HOME, ses parents ni la racine du disque : repli sur le dossier scanné.
 */
export async function projectRoot(root: string, gitRoot: string | null, home: string = homedir()): Promise<string> {
  if (gitRoot) return forbiddenRoot(gitRoot, home) ? root : gitRoot;
  let dir = root;
  for (let i = 0; i < 8; i++) {
    if (forbiddenRoot(dir, home)) break;
    for (const m of MARKERS) {
      if (
        await stat(join(dir, m)).then(
          () => true,
          () => false,
        )
      )
        return dir;
    }
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return root;
}

/**
 * Liste du projet pour les conditions `when`, ou null si elle dépasse le plafond.
 * Limite connue : seuls les `exclude` du .dotation.yml de la racine résolue s'appliquent (chargé ici, sans l'autorité du dossier scanné).
 */
export async function listProject(
  top: string,
  gitRoot: string | null,
  fallbackExclude: readonly string[],
  cap: number = houseLimits.maxProjectFiles,
): Promise<ScanFile[] | null> {
  const exclude = await loadConfig(top).then(
    (c) => c.exclude,
    () => fallbackExclude,
  );
  if (gitRoot) {
    const fs = (await collectFiles(top, { scope: "project", staged: false, excludes: exclude })).files;
    return fs.length > cap ? null : fs;
  }
  const excludes = [...DEFAULT_EXCLUDES, ...exclude];
  const out: ScanFile[] = [];
  const walk = async (dir: string): Promise<boolean> => {
    let entries: Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return true;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const abs = join(dir, e.name);
      const rel = relative(top, abs).split(sep).join("/");
      if (e.isDirectory()) {
        if (e.name.startsWith(".") && !HIDDEN_DIRS_ALLOWED.has(e.name)) continue;
        if (matchAny(`${rel}/`, excludes) || matchAny(`${rel}/x`, excludes)) continue;
        if (!(await walk(abs))) return false;
      } else if (e.isFile() && !matchAny(rel, excludes)) {
        if (out.length >= cap) return false;
        out.push({ path: rel, read: () => readText(abs) });
      }
    }
    return true;
  };
  if (!(await walk(top))) return null;
  return out.sort((a, b) => (a.path < b.path ? -1 : 1));
}
