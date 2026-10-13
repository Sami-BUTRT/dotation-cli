import { relative, sep } from "node:path";
import { hasCommand, run } from "../core/exec.js";
import { isEnvFile } from "../core/files.js";
import type { Finding, Severity } from "../core/finding.js";
import { redactLine } from "../core/mask.js";
import { type Engine, result, shortError } from "./engine.js";

interface GitleaksLeak {
  RuleID: string;
  File: string;
  StartLine: number;
  Secret: string;
  Match: string;
  Line?: string;
}

// Secrets dont la fuite donne directement accès à de l'argent ou à de l'infrastructure.
const CRITICAL =
  /aws|gcp|azure|stripe|private-key|github|gitlab|openai|anthropic|supabase|slack|twilio|sendgrid|digitalocean|heroku|npm|pypi|shopify/i;

export function gitleaksSeverity(ruleId: string): Severity {
  if (CRITICAL.test(ruleId)) return "critical";
  if (/generic|jwt|password/i.test(ruleId)) return "high";
  return "high";
}

/**
 * Rôle d'un jeton Supabase : JWT dont la charge utile porte « role » (anon, service_role), ou clé « sb_publishable_ ».
 * La clé anon / publishable est publique par conception (elle est dans le front de toute app Supabase) : ce n'est pas une fuite.
 */
export function supabaseRole(secret: string): string | null {
  if (secret.startsWith("sb_publishable_")) return "anon";
  if (secret.startsWith("sb_secret_")) return "service_role";
  const payload = jwtPayload(secret);
  if (!payload) return null;
  return typeof payload.role === "string" && /supabase/.test(String(payload.iss)) ? payload.role : null;
}

/** Charge utile d'un JWT complet (trois parties, JSON lisible), sinon null. */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.trim().split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return null;
  try {
    const v: unknown = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8"));
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Transforme le rapport JSON de Gitleaks en Finding. Le secret brut est utilisé ici pour être masqué,
 * puis oublié : il ne figure dans aucun champ du Finding.
 */
export function parseGitleaks(json: string, root: string, msg: import("../i18n/index.js").Messages): Finding[] {
  const leaks = (JSON.parse(json || "[]") as GitleaksLeak[])
    .filter((l) => supabaseRole(l.Secret) !== "anon")
    // Exemple tronqué dans une doc (« eyJhbGci... ») : un JWT illisible ou une valeur coupée par « ... » n'est pas un jeton.
    .filter((l) => !l.Secret.endsWith("...") && !l.Secret.endsWith("…"))
    .filter((l) => !(/^jwt$/i.test(l.RuleID) || l.Secret.startsWith("eyJ")) || jwtPayload(l.Secret) !== null);
  return leaks.map((l) => {
    const file = relative(root, l.File).split(sep).join("/") || l.File;
    const snippet = redactLine(l.Line ?? l.Match, [l.Secret]);
    return {
      id: `gitleaks:${l.RuleID}`,
      engine: "gitleaks",
      severity: supabaseRole(l.Secret) === "service_role" ? "critical" : gitleaksSeverity(l.RuleID),
      category: "secret",
      title: `${msg.gitleaks.title} (${l.RuleID})`,
      explanation: msg.gitleaks.explanation,
      fix: msg.gitleaks.fix,
      file,
      line: l.StartLine,
      snippet,
    };
  });
}

export const gitleaksEngine: Engine = {
  id: "gitleaks",
  async scan(ctx) {
    if (ctx.config.engines.gitleaks === false) return result("gitleaks", "disabled");
    if (!(await hasCommand("gitleaks", ["version"])))
      return result("gitleaks", "missing", [], ctx.msg.install.gitleaks);

    const common = [
      "--report-format",
      "json",
      "--report-path",
      "-",
      "--no-banner",
      "--exit-code",
      "0",
      "--log-level",
      "error",
    ];
    const args =
      ctx.staged && ctx.fileSet.gitRoot
        ? ["git", "--staged", ...common, ctx.fileSet.gitRoot]
        : ["dir", ...common, "--max-target-megabytes", "1", ctx.root];
    const r = await run("gitleaks", args, { timeoutMs: ctx.timeoutMs, cwd: ctx.root });
    if (r.timedOut) return result("gitleaks", "timeout", [], String(ctx.timeoutMs / 1000));
    if (r.code !== 0) return result("gitleaks", "failed", [], shortError(r.stderr));

    const base = ctx.staged && ctx.fileSet.gitRoot ? ctx.fileSet.gitRoot : ctx.root;
    const inScope = new Set(ctx.fileSet.files.map((f) => f.path));
    const findings = parseGitleaks(r.stdout, base, ctx.msg)
      .map((f) =>
        base === ctx.root ? f : { ...f, file: relative(ctx.root, `${base}/${f.file}`).split(sep).join("/") },
      )
      // Hors périmètre (node_modules, fichiers ignorés…) ou secret rangé dans un .env non versionné : rien à dire.
      .filter((f) => inScope.has(f.file))
      .filter((f) => !(isEnvFile(f.file) && !ctx.fileSet.tracked?.has(f.file)));
    return result("gitleaks", "ok", findings);
  },
};
