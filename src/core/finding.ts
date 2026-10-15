// Type unique de résultat : tous les moteurs (règles maison, Gitleaks, Semgrep, OSV-Scanner) produisent des Finding.

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ENGINE_IDS = ["house", "gitleaks", "semgrep", "osv"] as const;
export type EngineId = (typeof ENGINE_IDS)[number];

/** Famille de problème ; sert au dédoublonnage entre moteurs (un secret vu par Gitleaks et par une règle maison). */
export type Category = "secret" | "config" | "code" | "dependency" | "access";

export interface Finding {
  /** Identifiant stable de la règle (DOT-SEC-001, gitleaks:aws-access-token, semgrep:sql-injection, osv:GHSA-…). */
  id: string;
  engine: EngineId;
  severity: Severity;
  category: Category;
  /** Textes déjà traduits dans la langue du rapport. */
  title: string;
  explanation: string;
  fix: string;
  /** Chemin relatif à la racine du scan, séparateurs « / ». */
  file: string;
  /** Ligne (1 = première) ; 0 quand le problème porte sur le fichier entier. */
  line: number;
  /** Extrait de la ligne, secrets masqués. Jamais la valeur complète d'un secret. */
  snippet: string;
  /** Références OWASP et CWE (voir core/refs.ts) ; absent si la règle n'en déclare pas. */
  refs?: string[];
  /** Constat d'une règle écrite dans le dépôt analysé (.dotation/rules) : ses textes viennent de l'auteur du dépôt. */
  projectRule?: true;
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function severityRank(s: Severity): number {
  return RANK[s];
}

export function isSeverity(v: string): v is Severity {
  return (SEVERITIES as readonly string[]).includes(v);
}

export function atLeast(s: Severity, threshold: Severity): boolean {
  return RANK[s] >= RANK[threshold];
}

/** Tri : plus grave d'abord, puis fichier, puis ligne. */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    RANK[b.severity] - RANK[a.severity] || a.file.localeCompare(b.file) || a.line - b.line || a.id.localeCompare(b.id)
  );
}
