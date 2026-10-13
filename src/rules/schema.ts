import { z } from "zod";
import { SEVERITIES } from "../core/finding.js";

// Format d'une règle maison (fichier YAML). Exemple commenté : cli/rules/README.md.

const TextsSchema = z
  .object({ title: z.string().min(1), explanation: z.string().min(1), fix: z.string().min(1) })
  .strict();

const LangTexts = z
  .object({
    fr: TextsSchema.optional(),
    en: TextsSchema.optional(),
    es: TextsSchema.optional(),
    zh: TextsSchema.optional(),
  })
  .strict()
  .refine((t) => t.en !== undefined || t.fr !== undefined, 'at least an "en" or "fr" text is required');

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
    /** Le fichier doit contenir ce motif quelque part (ex. "use client") pour que la règle s'applique. */
    fileMustMatch: z.string().optional(),
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

/** Supabase : table créée dans le schéma public sans « enable row level security ». */
const SupabaseRlsDetector = z.object({ type: z.literal("supabase-rls"), files: Files }).strict();

export const DetectorSchema = z.discriminatedUnion("type", [
  RegexDetector,
  TrackedFileDetector,
  NotIgnoredDetector,
  SupabaseRlsDetector,
  HiddenCodeDetector,
]);

export const CATEGORIES = ["secret", "config", "code", "dependency", "access"] as const;

export const RuleSchema = z
  .object({
    id: z.string().regex(/^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$/, "expected id: PREFIX-XXX-000"),
    severity: z.enum(SEVERITIES),
    category: z.enum(CATEGORIES),
    detector: DetectorSchema,
    text: LangTexts,
  })
  .strict();

export type Rule = z.infer<typeof RuleSchema>;
export type Detector = z.infer<typeof DetectorSchema>;
export type RegexRule = Rule & { detector: z.infer<typeof RegexDetector> };
