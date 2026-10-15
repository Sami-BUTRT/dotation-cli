import type { Messages } from "./types.js";

export const en: Messages = {
  severity: { critical: "Critical", high: "High", medium: "Medium", low: "Low" },
  report: {
    heading: "dotation: your code hygiene",
    target: (path, files) => `Scanned: ${path} (${files} file${files === 1 ? "" : "s"})`,
    clean: "Nothing to report. Your code looks clean, nice work.",
    score: (s) => `Hygiene score: ${s}/100`,
    counts: (parts) => `Found: ${parts}`,
    more: (n) => `… and ${n} more. Run again with --all to see everything.`,
    why: "Why",
    fix: "How to fix",
    refs: "References",
    projectRule: "project rule",
    engines: "Engines",
    engineOk: (n) => `ok (${n} finding${n === 1 ? "" : "s"})`,
    engineMissing: (hint) => `not available. ${hint}`,
    engineDisabled: "disabled in .dotation.yml",
    engineFailed: (reason) => `failed: ${reason}`,
    engineTimeout: (s) => `stopped after ${s}s (raise --timeout if needed)`,
    failOn: (t) => `Exit code 1: at least one "${t}" or worse issue.`,
    noFiles: "No files to scan here.",
    protectedRejected: (ids) =>
      ids.map((id) => `protected rule ${id}: replacement by .dotation/rules was ignored`).join("; "),
    baselineHidden: (n, file) =>
      `${n} already known finding${n > 1 ? "s" : ""} hidden by ${file}: use --no-baseline to see everything.`,
    baselineInvalid: (reason, file) =>
      `Baseline ${file} ignored (${reason}): all findings are shown. Recreate it with "dotation baseline" if you wrote it.`,
    projectTooLarge: "project too large: conditions evaluated on the scanned files only",
    ruleFileSkipped: (file, reason) => `project rules skipped (.dotation/rules/${file}): ${reason}`,
    suppressed: (ignored, disabled, overridden) => {
      const parts = [
        ignored > 0 ? `${ignored} finding${ignored > 1 ? "s" : ""} (dotation-ignore comment)` : "",
        disabled > 0 ? `${disabled} finding${disabled > 1 ? "s" : ""} (disable in .dotation.yml)` : "",
        overridden.length > 0 ? `rules replaced by .dotation/rules: ${overridden.join(", ")}` : "",
      ].filter(Boolean);
      return `Set aside by the project's settings: ${parts.join("; ")}. If you didn't write these settings yourself (cloned project, starter), check them before running the project.`;
    },
  },
  engineNames: {
    house: "dotation rules",
    gitleaks: "Gitleaks (secrets)",
    semgrep: "Semgrep (code)",
    osv: "OSV-Scanner (dependencies)",
  },
  install: {
    gitleaks: "Install it to go further: brew install gitleaks (or https://github.com/gitleaks/gitleaks/releases)",
    semgrep: "Install it to go further: pipx install semgrep (or brew install semgrep)",
    osv: "Install it to go further: brew install osv-scanner (or https://github.com/google/osv-scanner/releases), then run dotation update-db",
  },
  gitleaks: {
    title: "Secret in the code",
    explanation:
      "A hardcoded key or token ends up in git history: anyone who sees the repo (or a bot crawling GitHub) can use it.",
    fix: "Revoke the key with the provider and create a new one. Keep it in an environment variable (an untracked .env) or a secrets manager.",
  },
  osv: {
    title: (pkg, v, n) => `${pkg}@${v}: ${n > 1 ? `${n} known vulnerabilities` : "a known vulnerability"}`,
    explanation: (summary, ids) =>
      `${summary ? `${summary}. ` : "This version has a published vulnerability. "}References: ${ids.slice(0, 5).join(", ")}${ids.length > 5 ? "…" : ""}.`,
    fix: (pkg, fixed) => (fixed ? `Update ${pkg} to ${fixed} or later.` : `Update ${pkg} to a fixed version.`),
    dbMissing: "Vulnerability database missing: run “dotation update-db” once (download only, nothing is sent).",
    dbStale: (d) => `vulnerability database is ${d} days old: run “dotation update-db”`,
  },
  banner: {
    project: "Project:",
    plan: "Plan:",
    planFree: "Free",
    planPro: "Pro",
    planProUnknown: "Pro? (check with `dotation whoami`)",
  },
  cli: {
    description:
      "Finds basic security slip-ups before you ship. Scans run on your machine: nothing is sent unless you ask.",
    scan: "Scan a project, a folder or a file",
    init: "Add the config file, a pre-commit hook and a GitHub Action",
    mcp: "Start the MCP server (for Claude Code, Cursor…)",
    updateDb: "Download the vulnerability database for OSV-Scanner (download only: nothing is sent)",
    notGit: "--staged needs a git repository.",
    badPath: (p) => `Path not found: ${p}`,
    initWrote: (p) => `created: ${p}`,
    initSkipped: (p) => `already there, left untouched: ${p}`,
    initHookExists: (p) =>
      `a hook already exists (${p}): add the line “dotation scan --staged” to it, or run again with --force`,
    updateDbDone: "Vulnerability database is up to date.",
    sbom: "List every project dependency as a CycloneDX SBOM, from the lockfiles, without network",
    baseline: "Freeze the current findings in .dotation/baseline.json: later scans only report new ones",
    baselineWritten: (path, n) =>
      `Baseline written to ${path}: ${n} finding${n === 1 ? "" : "s"} frozen (no secret value stored, only hashes). Later scans only report new ones.`,
    baselineUnsafe: (path) =>
      `Refusing to write ${path}: .dotation or the file is a symbolic link or not a regular file. Nothing was written.`,
    baselineIncomplete: (engines) =>
      `Baseline not written: engine(s) failed (${engines}), so it would be incomplete. Fix them or use --allow-partial.`,
    sbomWritten: (path, n) => `SBOM written to ${path}: ${n} component${n === 1 ? "" : "s"}.`,
    agent:
      "Set up AI coding agents: install the dotation skill and register the MCP server (Claude Code, Cursor, VS Code, Codex…)",
  },
  agent: {
    updated: (p) => `updated: ${p}`,
    invalid: (p, entry) =>
      `could not read ${p} as plain JSON, left untouched: add this server to it yourself: ${entry}`,
    userMcp: (cmd) => `For Claude Code in every project: claude mcp add --scope user dotation -- ${cmd}`,
    next: "Restart your agent (or reload its MCP servers) to pick this up. Then ask it: “check this project with dotation”.",
    badTarget: (t) => `unknown target: ${t} (expected claude, agents, cursor, vscode or all)`,
  },
  cloud: {
    login: "Connect the CLI to your dotation.app account (code to confirm in the browser)",
    logout: "Forget the key saved on this machine",
    whoami: "Show the account and plan of the saved key",
    rules: "Signed rule packs",
    rulesUpdate: "Download and verify rule packs (open ones, and Pro ones depending on your plan)",
    explain: "Explanation or fix for a finding by the AI assistant (Pro plan): dotation explain file:line",
    upload: "upload the report to your account (metadata only, never your code)",
    loginOpen: (url, code) => `Open ${url}\nthen check that the code shown is: ${code}`,
    loginWaiting: "Waiting for you to confirm in the browser…",
    loginDone: (p) => `Signed in. Key saved in ${p} (readable by you only).`,
    loginDenied: "Sign-in denied in the browser. Nothing was saved.",
    loginExpired: "The code expired. Run “dotation login” again.",
    logoutDone: (p) => `Key forgotten (${p} deleted).`,
    logoutNone: "No key saved on this machine.",
    logoutRevoke: (u) => `To revoke it on the server too: ${u}`,
    whoamiLine: (e, plan, via) => `${e} · ${plan} plan · ${via}`,
    notLoggedIn: "Not signed in: run “dotation login” (or set DOTATION_TOKEN in CI).",
    sessionExpired: "This key is no longer valid (revoked or expired): run “dotation login” again.",
    network: (u) => `Service unreachable (${u}). Your scan is still available locally.`,
    rateLimited: (s) => `Too many requests: try again in ${s} s.`,
    uploadDone: (n, f, x) => `Report uploaded: ${n} findings (${f} new, ${x} fixed since the last upload).`,
    uploadPlan: "Scan history is included in the Pro plan. The local scan stays complete.",
    uploadQuota: "Monthly report quota reached; it resets on the 1st of the month.",
    uploadProjects: "Maximum number of projects reached for your plan (use --project to reuse a project).",
    rulesInstalled: (n, v) => `${n} ${v}: installed and verified`,
    rulesUnchanged: (n, v) => `${n} ${v}: already up to date`,
    rulesLocked: (n) => `${n}: Pro plan only`,
    rulesUntrusted: (n) => `${n}: signed with a key this CLI version doesn't know, skipped`,
    rulesInvalid: (n, d) => `${n}: rejected (${d})`,
    rulesNone: "No rule packs published yet.",
    explainBadTarget: "Give the finding as file:line (e.g. src/lib/supabase.ts:12).",
    explainNoFinding: (f, l) => `No finding at ${f}:${l}.`,
    explainPick: (lines) => `Findings in this file, lines: ${lines}`,
    explainMasked: (l, s) => `Secrets masked before sending: ${l} here, ${s} on the server.`,
    explainPlan: "The AI assistant is included in the Pro plan.",
    explainUnavailable: "The AI assistant isn't available yet.",
    explainQuota: "Monthly assistant quota reached; it resets on the 1st of the month.",
  },
};
