import type { Config } from "../core/config.js";
import type { FileSet, Scope } from "../core/files.js";
import type { EngineId, Finding } from "../core/finding.js";
import type { Lang, Messages } from "../i18n/index.js";

export interface ScanContext {
  /** Dossier analysé (absolu). */
  root: string;
  fileSet: FileSet;
  scope: Scope;
  staged: boolean;
  lang: Lang;
  msg: Messages;
  config: Config;
  timeoutMs: number;
  /** Dossiers de règles maison supplémentaires (ex. .dotation/rules du projet). */
  extraRuleDirs: string[];
}

export type EngineState = "ok" | "missing" | "disabled" | "failed" | "timeout";

export interface EngineStatus {
  engine: EngineId;
  state: EngineState;
  count: number;
  /** Commande d'installation (missing) ou raison de l'échec (failed), déjà traduite. Jamais de secret. */
  detail?: string;
}

export interface EngineResult {
  status: EngineStatus;
  findings: Finding[];
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
