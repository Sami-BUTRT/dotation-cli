import type { Config } from "../core/config.js";
import type { FileSet, Scope } from "../core/files.js";
import type { EngineId, Finding } from "../core/finding.js";
import type { Messages } from "../i18n/index.js";

export interface ScanContext {
  /** Dossier analysé (absolu). */
  root: string;
  fileSet: FileSet;
  scope: Scope;
  staged: boolean;
  msg: Messages;
  config: Config;
  timeoutMs: number;
  /** Dossiers de règles maison supplémentaires et vérifiés (packs installés). */
  extraRuleDirs: string[];
  /** Règles du projet (.dotation/rules) : écrites par l'auteur du dépôt, donc sans confiance. */
  projectRuleDir?: string;
}

export type EngineState = "ok" | "missing" | "disabled" | "failed" | "timeout";

export interface EngineStatus {
  engine: EngineId;
  state: EngineState;
  count: number;
  /** Commande d'installation (missing) ou raison de l'échec (failed), déjà traduite. Jamais de secret. */
  detail?: string;
}

/** Ce que les règles du projet (.dotation/rules) ont changé ou n'ont pas pu changer, remonté par le moteur maison. */
export interface RuleNotices {
  overridden: string[];
  protectedRejected: string[];
  skippedFiles: { file: string; reason: string }[];
  /** Liste du projet trop grande : conditions évaluées sur les fichiers scannés seulement. */
  projectTooLarge?: boolean;
}

export interface EngineResult {
  status: EngineStatus;
  findings: Finding[];
  ruleNotices?: RuleNotices;
}

export interface Engine {
  id: EngineId;
  scan(ctx: ScanContext): Promise<EngineResult>;
}

export function result(engine: EngineId, state: EngineState, findings: Finding[] = [], detail?: string): EngineResult {
  return { status: { engine, state, count: findings.length, ...(detail ? { detail } : {}) }, findings };
}

/** Message d'erreur d'un outil, réduit à une ligne courte (les sorties d'outils peuvent être longues). */
export function shortError(stderr: string): string {
  const line = stderr.split("\n").find((l) => l.trim().length > 0) ?? "erreur inconnue";
  return line.trim().slice(0, 160);
}
