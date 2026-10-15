import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "yaml";
import { z } from "zod";
import { SEVERITIES } from "./finding.js";

// Configuration du projet : .dotation.yml à la racine du scan. Tout est facultatif.
export const ConfigSchema = z
  .object({
    failOn: z.enum(SEVERITIES).optional(),
    /** Legacy setting: accepted but ignored (the CLI is English-only). */
    lang: z.string().optional(),
    /** Globs exclus en plus des dossiers par défaut (node_modules, dist…). */
    exclude: z.array(z.string()).default([]),
    /** Règles désactivées (identifiants exacts, ex. DOT-CFG-002 ou gitleaks:generic-api-key). */
    disable: z.array(z.string()).default([]),
    engines: z
      .object({
        gitleaks: z.boolean().default(true),
        semgrep: z.boolean().default(true),
        osv: z.boolean().default(true),
      })
      .partial()
      .default({}),
    /** Délai maximal par moteur, en secondes. */
    timeout: z.number().int().min(5).max(3600).optional(),
  })
  .strict();

export type Config = z.infer<typeof ConfigSchema>;

export const CONFIG_FILE = ".dotation.yml";

export async function loadConfig(root: string): Promise<Config> {
  let raw: string;
  try {
    raw = await readFile(join(root, CONFIG_FILE), "utf8");
  } catch {
    return ConfigSchema.parse({});
  }
  const parsed: unknown = parse(raw) ?? {};
  const r = ConfigSchema.safeParse(parsed);
  if (!r.success) {
    throw new Error(
      `${CONFIG_FILE}: ${r.error.issues.map((i) => `${i.path.join(".") || "(racine)"} ${i.message}`).join("; ")}`,
    );
  }
  return r.data;
}
