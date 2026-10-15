import { z } from "zod";
import { SEVERITIES } from "../core/finding.js";
import { REF_PATTERN } from "../core/refs.js";

// Format d'une règle maison (fichier YAML). Exemple commenté : cli/rules/README.md.

const TextsSchema = z
  .object({ title: z.string().min(1), explanation: z.string().min(1), fix: z.string().min(1) })
  .strict();

// English preferred. Older packs and project rules may carry only fr (shown as-is when no en exists);
// es/zh blocks are accepted, then dropped. At least en or fr is required.
const LangTexts = z
  .object({
    en: TextsSchema.optional(),
    fr: TextsSchema.optional(),
    es: z.unknown().optional(),
    zh: z.unknown().optional(),
  })
  .strict()
  .refine((t) => t.en !== undefined || t.fr !== undefined, { message: "text needs en (or fr)" })
  .transform((t) => ({ en: (t.en ?? t.fr) as z.infer<typeof TextsSchema> }));

const Files = z.array(z.string().min(1)).min(1);

/** Motif cherché ligne par ligne. */
const RegexDetector = z
  .object({
    type: z.literal("regex"),
    files: Files,
    exclude: z.array(z.string()).default([]),
    pattern: z.string().min(1),
    /** Drapeaux JS : seul « i » est permis (insensible à la casse). */
    flags: z.enum(["", "i"]).default(""),
    /** Motifs qui annulent un résultat sur la même ligne (valeurs d'exemple, variables d'environnement…). */
    ignoreIf: z.array(z.string()).default([]),
    /** Groupe nommé contenant un secret : masqué dans l'extrait. */
    secretGroup: z.string().optional(),
    /** Le fichier doit contenir ce motif (ou tous ces motifs) quelque part (ex. "use client") pour que la règle s'applique. */
    fileMustMatch: z.union([z.string(), z.array(z.string()).min(1)]).optional(),
    /** Le fichier est ignoré s'il contient l'un de ces motifs (ex. une vérification de session ou de signature). */
    unlessFile: z.array(z.string()).default([]),
    /** Un seul constat par fichier (le premier) : pour les règles qui portent sur le fichier entier. */
    firstOnly: z.boolean().default(false),
    /** Un seul constat par fichier (le dernier) : ex. la dernière étape FROM d'un Dockerfile. */
    lastOnly: z.boolean().default(false),
    /** Ignore les fichiers .env non versionnés (y garder un secret est la bonne pratique). */
    skipUntrackedEnv: z.boolean().default(false),
  })
  .strict();

/** Fichier sensible suivi par git (.env, clé privée…). */
const TrackedFileDetector = z
  .object({
    type: z.literal("tracked-file"),
    files: Files,
    exclude: z.array(z.string()).default([]),
    /** Sévérité d'un fichier .env versionné qui ne contient que des variables publiques (VITE_, NEXT_PUBLIC_…). */
    publicEnvSeverity: z.enum(SEVERITIES).optional(),
  })
  .strict();

/** Fichier présent dans le projet mais pas ignoré par git. */
const NotIgnoredDetector = z
  .object({
    type: z.literal("not-gitignored"),
    /** Nom testé auprès de git (ex. « .env »). */
    path: z.string().min(1),
    /** La règle ne s'applique que si l'un de ces fichiers existe (signe d'une application). */
    when: Files,
  })
  .strict();

/** Code caché après une longue suite d'espaces (technique des faux dépôts « starter » piégés). */
const HiddenCodeDetector = z
  .object({
    type: z.literal("hidden-code"),
    files: Files,
    exclude: z.array(z.string()).default([]),
    /** Nombre minimal d'espaces ou tabulations consécutifs avant le code. */
    minSpaces: z.number().int().min(20).default(150),
  })
  .strict();

/** Manifeste à la racine du projet sans aucun des fichiers attendus à côté (ex. package.json sans lockfile). */
const MissingSiblingDetector = z
  .object({
    type: z.literal("missing-sibling"),
    /** Noms de fichiers cherchés à la racine du projet analysé. */
    files: Files,
    /** Le manifeste doit contenir ce motif (ex. des dépendances déclarées). */
    fileMustMatch: z.string().optional(),
    /** Il suffit que l'un d'eux existe. */
    siblings: Files,
  })
  .strict();

/** Configuration de serveurs MCP (.mcp.json, .cursor/mcp.json, .vscode/mcp.json…). */
const McpConfigDetector = z
  .object({
    type: z.literal("mcp-config"),
    files: Files,
    /** unpinned : paquet lancé par npx / uvx sans version ; inline-secret : secret écrit dans env / args / headers ;
     * insecure-url : serveur distant en http://. */
    check: z.enum(["unpinned", "inline-secret", "insecure-url"]),
  })
  .strict();

/** Supabase : table créée dans le schéma public sans « enable row level security ». */
const SupabaseRlsDetector = z
  .object({
    type: z.literal("supabase-rls"),
    files: Files,
    /** La règle ne s'applique que si l'une de ces conditions est vraie : un fichier présent (et contenant le motif). */
    when: z.array(z.object({ files: Files, pattern: z.string().optional() }).strict()).default([]),
  })
  .strict();

/** Supabase : instruction SQL (découpée sur « ; », commentaires et chaînes respectés) qui correspond à un motif. */
const SqlStatementDetector = z
  .object({
    type: z.literal("sql-statement"),
    files: Files,
    when: z.array(z.object({ files: Files, pattern: z.string().optional() }).strict()).default([]),
    /** Motif (insensible à la casse) que l'instruction entière doit contenir ; les quantificateurs doivent être bornés. */
    pattern: z.string().min(1),
    /** Autres motifs qui doivent aussi correspondre. */
    also: z.array(z.string()).default([]),
    /** L'instruction est ignorée si l'un de ces motifs correspond. */
    unless: z.array(z.string()).default([]),
  })
  .strict();

/** Dépendance dont le nom ressemble beaucoup à celui d'un paquet très populaire (typosquatting, noms inventés par une IA). */
const LookalikePackageDetector = z
  .object({
    type: z.literal("lookalike-package"),
    /** Manifestes lus : package.json, requirements*.txt, pyproject.toml. Les textes peuvent utiliser {name} et {similar}. */
    files: Files,
  })
  .strict();

export const DetectorSchema = z.discriminatedUnion("type", [
  RegexDetector,
  TrackedFileDetector,
  NotIgnoredDetector,
  SupabaseRlsDetector,
  SqlStatementDetector,
  HiddenCodeDetector,
  MissingSiblingDetector,
  McpConfigDetector,
  LookalikePackageDetector,
]);

export const CATEGORIES = ["secret", "config", "code", "dependency", "access"] as const;

export const RuleSchema = z
  .object({
    id: z.string().regex(/^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$/, "expected id: PREFIX-XXX-000"),
    severity: z.enum(SEVERITIES),
    category: z.enum(CATEGORIES),
    detector: DetectorSchema,
    /** Références OWASP (A01:2025, API1:2023, LLM05:2025, MCP04:2025, NHI7:2025, CICD-SEC-4) et CWE (CWE-79). */
    refs: z
      .array(z.string().regex(REF_PATTERN, "expected an OWASP or CWE reference, e.g. A01:2025 or CWE-79"))
      .default([]),
    text: LangTexts,
  })
  .strict();

export type Rule = z.infer<typeof RuleSchema>;
export type Detector = z.infer<typeof DetectorSchema>;
export type RegexRule = Rule & { detector: z.infer<typeof RegexDetector> };
