import type { EngineId, Severity } from "../core/finding.js";

export interface Texts {
  title: string;
  explanation: string;
  fix: string;
}

export interface Messages {
  severity: Record<Severity, string>;
  report: {
    heading: string;
    target: (path: string, files: number) => string;
    clean: string;
    score: (score: number) => string;
    counts: (parts: string) => string;
    more: (hidden: number) => string;
    why: string;
    fix: string;
    refs: string;
    projectRule: string;
    engines: string;
    engineOk: (count: number) => string;
    engineMissing: (hint: string) => string;
    engineDisabled: string;
    engineFailed: (reason: string) => string;
    engineTimeout: (seconds: number) => string;
    failOn: (threshold: string) => string;
    noFiles: string;
    suppressed: (ignored: number, disabled: number, overridden: string[]) => string;
    protectedRejected: (ids: string[]) => string;
    baselineHidden: (n: number, file: string) => string;
    baselineInvalid: (reason: string, file: string) => string;
    projectTooLarge: string;
    ruleFileSkipped: (file: string, reason: string) => string;
  };
  engineNames: Record<EngineId, string>;
  install: { gitleaks: string; semgrep: string; osv: string };
  gitleaks: Texts;
  osv: {
    title: (pkg: string, version: string, count: number) => string;
    explanation: (summary: string, ids: string[]) => string;
    fix: (pkg: string, fixed: string | null) => string;
    dbMissing: string;
    dbStale: (days: number) => string;
  };
  banner: { project: string; plan: string; planFree: string; planPro: string; planProUnknown: string };
  cli: {
    description: string;
    scan: string;
    init: string;
    mcp: string;
    updateDb: string;
    sbom: string;
    sbomWritten: (path: string, count: number) => string;
    baseline: string;
    baselineWritten: (path: string, count: number) => string;
    baselineUnsafe: (path: string) => string;
    baselineIncomplete: (engines: string) => string;
    notGit: string;
    badPath: (path: string) => string;
    initWrote: (path: string) => string;
    initSkipped: (path: string) => string;
    initHookExists: (path: string) => string;
    updateDbDone: string;
    agent: string;
  };
  /** « dotation agent » : skill et serveur MCP pour les assistants de code. */
  agent: {
    updated: (path: string) => string;
    invalid: (path: string, entry: string) => string;
    userMcp: (command: string) => string;
    next: string;
    badTarget: (target: string) => string;
  };
  /** Service en ligne (facultatif) : connexion, envoi des rapports, packs de règles, assistant IA. */
  cloud: {
    login: string;
    logout: string;
    whoami: string;
    rules: string;
    rulesUpdate: string;
    explain: string;
    upload: string;
    loginOpen: (url: string, code: string) => string;
    loginWaiting: string;
    loginDone: (path: string) => string;
    loginDenied: string;
    loginExpired: string;
    logoutDone: (path: string) => string;
    logoutNone: string;
    logoutRevoke: (url: string) => string;
    whoamiLine: (email: string, plan: string, via: string) => string;
    notLoggedIn: string;
    sessionExpired: string;
    network: (url: string) => string;
    rateLimited: (seconds: number) => string;
    uploadDone: (findings: number, fresh: number, fixed: number) => string;
    uploadPlan: string;
    uploadQuota: string;
    uploadProjects: string;
    rulesInstalled: (name: string, version: string) => string;
    rulesUnchanged: (name: string, version: string) => string;
    rulesLocked: (name: string) => string;
    rulesUntrusted: (name: string) => string;
    rulesInvalid: (name: string, detail: string) => string;
    rulesNone: string;
    explainBadTarget: string;
    explainNoFinding: (file: string, line: number) => string;
    explainPick: (lines: string) => string;
    explainMasked: (local: number, server: number) => string;
    explainPlan: string;
    explainUnavailable: string;
    explainQuota: string;
  };
}

/** Langues partielles : ce qui manque vient de l'anglais. */
export type PartialMessages = { [K in keyof Messages]?: Partial<Messages[K]> };
