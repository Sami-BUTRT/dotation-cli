// Baseline : geler les constats d'un projet existant pour ne remonter que les nouveaux.
// Le fichier .dotation/baseline.json vient du dépôt analysé, donc d'un éventuel attaquant : il est validé (taille,
// forme), ne masque jamais PROTECTED_RULES (voir scan.ts) et ne contient jamais de valeur de secret, seulement des empreintes.
import { createHash } from "node:crypto";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { z } from "zod";

export const BASELINE_PATH = ".dotation/baseline.json";
export const MAX_BASELINE_BYTES = 5 * 1024 * 1024;
export const MAX_BASELINE_ENTRIES = 40_000;

export interface BaselineEntry {
  ruleId: string;
  /** Chemin relatif, séparateurs « / ». */
  file: string;
  fingerprint: string;
}

const schema = z.object({
  version: z.literal(1),
  createdAt: z.string().max(64).optional(),
  tool: z.string().max(64).optional(),
  entries: z
    .array(z.object({ ruleId: z.string().max(300), file: z.string().max(1000), fingerprint: z.string().length(64) }))
    .max(MAX_BASELINE_ENTRIES),
});

/** Empreinte indépendante du numéro de ligne : règle + fichier + ligne normalisée (rognée, espaces réduits). */
export function fingerprint(ruleId: string, file: string, lineText: string, redacted = false): string {
  const normalised = lineText.trim().replace(/\s+/g, " ");
  // Constat de secret : `lineText` est l'extrait masqué tel qu'affiché, jamais la ligne brute (pas de force brute
  // possible sur un secret faible depuis le fichier commité). Le préfixe sépare les deux espaces d'empreintes.
  return createHash("sha256")
    .update(`${redacted ? "masked\0" : ""}${ruleId}\0${file}\0${normalised}`)
    .digest("hex");
}

export type BaselineLoad =
  | { state: "absent" }
  | { state: "invalid"; reason: "too-large" | "unreadable" | "malformed" | "too-many-entries" }
  | { state: "ok"; fingerprints: Set<string> };

export async function loadBaseline(path: string, root?: string): Promise<BaselineLoad> {
  const l = await lstat(path).catch(() => null);
  if (!l) return { state: "absent" };
  // Un lien symbolique (fichier ou dossier parent) n'est suivi que s'il reste dans le projet (jamais vers ~/.bashrc, /etc/…).
  // Toujours comparer les chemins réels : un dossier .dotation/ lui-même lien symbolique contourne le test sur le fichier.
  if (root) {
    const real = await realpath(path).catch(() => null);
    const base = await realpath(root).catch(() => null);
    const rel = real && base ? relative(base, real) : "..";
    if (rel === ".." || rel.startsWith("../") || rel.startsWith("..\\") || isAbsolute(rel))
      return { state: "invalid", reason: "unreadable" };
  }
  const s = await stat(path).catch(() => null);
  if (!s) return { state: "absent" };
  if (!s.isFile()) return { state: "invalid", reason: "unreadable" };
  if (s.size > MAX_BASELINE_BYTES) return { state: "invalid", reason: "too-large" };
  const text = await readFile(path, "utf8").catch(() => null);
  if (text === null) return { state: "invalid", reason: "unreadable" };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { state: "invalid", reason: "malformed" };
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    const tooMany = parsed.error.issues.some(
      (i) => i.code === "too_big" && i.path[0] === "entries" && i.path.length === 1,
    );
    return { state: "invalid", reason: tooMany ? "too-many-entries" : "malformed" };
  }
  return { state: "ok", fingerprints: new Set(parsed.data.entries.map((e) => e.fingerprint)) };
}

/** Entrées uniques, dans un ordre déterministe. */
export function sortEntries(entries: readonly BaselineEntry[]): BaselineEntry[] {
  const seen = new Set<string>();
  return entries
    .filter((e) => (seen.has(e.fingerprint) ? false : (seen.add(e.fingerprint), true)))
    .sort(
      (a, b) =>
        a.file.localeCompare(b.file) || a.ruleId.localeCompare(b.ruleId) || a.fingerprint.localeCompare(b.fingerprint),
    );
}

export function serializeBaseline(
  entries: readonly BaselineEntry[],
  version: string,
  createdAt = new Date().toISOString(),
) {
  return `${JSON.stringify({ version: 1, createdAt, tool: `dotation ${version}`, entries: sortEntries(entries) }, null, 2)}\n`;
}
