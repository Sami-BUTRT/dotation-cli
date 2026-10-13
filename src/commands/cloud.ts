// Commandes du service en ligne : login, logout, whoami, rules update, explain, et l'envoi de « scan --upload ».
// Chacune utilise le réseau parce qu'on la lance explicitement ; « dotation scan » seul n'en fait jamais rien.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Command } from "commander";
import { CloudError, request } from "../cloud/client.js";
import { apiUrl, credentialsPath, deleteCredentials, loadCredentials, saveCredentials } from "../cloud/config.js";
import { pollDevice, startDevice } from "../cloud/device.js";
import { explain, snippetAround } from "../cloud/explain.js";
import { updatePacks } from "../cloud/rulepacks.js";
import { buildPayload, upload } from "../cloud/upload.js";
import { detectLang, type Messages } from "../i18n/index.js";
import { type ScanReport, scan } from "../scan.js";

const EXIT_ERROR = 2;

/** Adresse du site (pages « Mon compte », « device ») déduite de l'adresse de l'API. */
export function siteUrl(api: string): string {
  const u = new URL(api);
  if (u.hostname.startsWith("api.")) u.hostname = `www.${u.hostname.slice(4)}`;
  return u.origin;
}

function err(s: string) {
  process.stderr.write(`${s}\n`);
}

/** Message lisible pour une erreur de l'API ; renvoie le code retour. */
export function reportCloudError(e: unknown, m: Messages, base: string, specific: Record<string, string> = {}): number {
  if (!(e instanceof CloudError)) {
    err(`dotation: ${e instanceof Error ? e.message : String(e)}`);
    return EXIT_ERROR;
  }
  if (specific[e.code]) err(specific[e.code] as string);
  else if (e.status === 0) err(m.cloud.network(base));
  else if (e.status === 401) err(m.cloud.sessionExpired);
  else if (e.status === 429) err(m.cloud.rateLimited(e.retryAfter ?? 60));
  else err(`dotation: ${e.message} (${e.status} ${e.code})`);
  return EXIT_ERROR;
}

async function requireCredentials(m: Messages) {
  const c = await loadCredentials();
  if (!c) err(m.cloud.notLoggedIn);
  return c;
}

export async function uploadReport(
  report: ScanReport,
  opts: { project?: string; hashPaths: boolean },
  m: Messages,
): Promise<void> {
  const c = await requireCredentials(m);
  if (!c) {
    process.exitCode = EXIT_ERROR;
    return;
  }
  try {
    const r = await upload(c.apiUrl, c.token, buildPayload(report, opts));
    err(m.cloud.uploadDone(r.findings, r.new, r.fixed));
  } catch (e) {
    process.exitCode = reportCloudError(e, m, c.apiUrl, {
      plan_required: m.cloud.uploadPlan,
      project_limit: m.cloud.uploadProjects,
      rate_limited: m.cloud.uploadQuota,
    });
  }
}

/** « fichier:ligne » → { file, line } ; null si mal formé. */
export function parseTarget(s: string): { file: string; line: number } | null {
  const m = /^(.+):(\d+)$/.exec(s);
  if (!m) return null;
  const line = Number.parseInt(m[2] as string, 10);
  return line > 0 ? { file: m[1] as string, line } : null;
}

/** `m` : messages d'exécution (langue choisie) ; `h` : aide, toujours en anglais. */
export function cloudCommands(program: Command, m: Messages, h: Messages = m): void {
  program
    .command("login")
    .description(h.cloud.login)
    .option("--api <url>", "API address (default: https://api.dotation.app)")
    .action(async (flags: { api?: string }) => {
      const base = apiUrl(process.env, flags.api);
      const scopes = ["account:read", "scans:read", "scans:write", "rules:read", "ai:use"];
      try {
        const start = await startDevice(base, scopes);
        process.stdout.write(
          `${m.cloud.loginOpen(start.verification_uri_complete ?? start.verification_uri, start.user_code)}\n`,
        );
        err(m.cloud.loginWaiting);
        const tok = await pollDevice(base, start);
        const path = await saveCredentials({
          apiUrl: base,
          token: tok.access_token,
          scopes: tok.scope.split(" "),
          createdAt: new Date().toISOString(),
        });
        process.stdout.write(`${m.cloud.loginDone(path)}\n`);
      } catch (e) {
        process.exitCode = reportCloudError(e, m, base, {
          access_denied: m.cloud.loginDenied,
          expired_token: m.cloud.loginExpired,
        });
      }
    });

  program
    .command("logout")
    .description(h.cloud.logout)
    .action(async () => {
      const c = await loadCredentials().catch(() => null);
      if (await deleteCredentials()) {
        process.stdout.write(`${m.cloud.logoutDone(credentialsPath())}\n`);
        process.stdout.write(
          `${m.cloud.logoutRevoke(`${siteUrl(c?.apiUrl ?? apiUrl())}/${detectLang() === "fr" ? "fr" : "en"}/account`)}\n`,
        );
      } else process.stdout.write(`${m.cloud.logoutNone}\n`);
    });

  program
    .command("whoami")
    .description(h.cloud.whoami)
    .action(async () => {
      const c = await requireCredentials(m);
      if (!c) {
        process.exitCode = EXIT_ERROR;
        return;
      }
      try {
        const me = await request<{ user: { email: string }; via: string }>(c.apiUrl, "/v1/me", { token: c.token });
        const rights = await request<{ plan: string }>(c.apiUrl, "/v1/entitlements", { token: c.token });
        process.stdout.write(`${m.cloud.whoamiLine(me.user.email, rights.plan, c.apiUrl)}\n`);
      } catch (e) {
        process.exitCode = reportCloudError(e, m, c.apiUrl);
      }
    });

  program
    .command("rules")
    .description(h.cloud.rules)
    .command("update")
    .description(h.cloud.rulesUpdate)
    .action(async () => {
      const c = await loadCredentials().catch(() => null);
      const base = c?.apiUrl ?? apiUrl();
      try {
        const out = await updatePacks(base, c?.token);
        if (out.length === 0) process.stdout.write(`${m.cloud.rulesNone}\n`);
        for (const r of out) {
          const line =
            r.status === "installed"
              ? m.cloud.rulesInstalled(r.name, r.version)
              : r.status === "unchanged"
                ? m.cloud.rulesUnchanged(r.name, r.version)
                : r.status === "locked"
                  ? m.cloud.rulesLocked(r.name)
                  : r.status === "untrusted"
                    ? m.cloud.rulesUntrusted(r.name)
                    : m.cloud.rulesInvalid(r.name, "detail" in r ? (r.detail ?? "") : "");
          process.stdout.write(`${line}\n`);
          if (r.status === "invalid") process.exitCode = EXIT_ERROR;
        }
      } catch (e) {
        process.exitCode = reportCloudError(e, m, base);
      }
    });

  program
    .command("explain")
    .description(h.cloud.explain)
    .argument("<target>", "file:line")
    .option("--fix", "suggest a fix instead of an explanation")
    .action(async (target: string, flags: { fix?: boolean }) => {
      const t = parseTarget(target);
      if (!t) {
        err(m.cloud.explainBadTarget);
        process.exitCode = EXIT_ERROR;
        return;
      }
      const c = await requireCredentials(m);
      if (!c) {
        process.exitCode = EXIT_ERROR;
        return;
      }
      const lang = detectLang() === "fr" ? "fr" : "en";
      const report = await scan(resolve(t.file), { lang: detectLang() });
      const finding = report.findings.find((f) => f.line === t.line);
      if (!finding) {
        err(m.cloud.explainNoFinding(t.file, t.line));
        const lines = [...new Set(report.findings.map((f) => f.line))].sort((a, b) => a - b);
        if (lines.length) err(m.cloud.explainPick(lines.join(", ")));
        process.exitCode = EXIT_ERROR;
        return;
      }
      const content = await readFile(resolve(t.file), "utf8");
      const snip = snippetAround(content, t.line);
      try {
        const r = await explain(
          c.apiUrl,
          c.token,
          { finding, snippet: snip.text, fix: flags.fix ?? false, lang },
          (s) => process.stdout.write(s),
        );
        process.stdout.write("\n");
        err(m.cloud.explainMasked(snip.masked, r.maskedServer));
      } catch (e) {
        process.exitCode = reportCloudError(e, m, c.apiUrl, {
          plan_required: m.cloud.explainPlan,
          ai_unavailable: m.cloud.explainUnavailable,
          rate_limited: m.cloud.explainQuota,
        });
      }
    });
}
