import { execFileSync } from "node:child_process";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll } from "vitest";
import { packagePath } from "../paths.js";

export const FIXTURES = packagePath("fixtures");

const created: string[] = [];
afterAll(async () => {
  await Promise.all(created.map((d) => rm(d, { recursive: true, force: true })));
});

export async function tempDir(prefix = "dotation-"): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  created.push(d);
  return d;
}

export function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.com", ...args], {
    cwd,
    encoding: "utf8",
  });
}

/** Copie une fixture dans un dépôt git neuf, tout commité (pour tester les règles « fichier versionné »). */
export async function fixtureRepo(name: "vulnerable-app" | "clean-app", commit = true): Promise<string> {
  const d = await tempDir(`dotation-${name}-`);
  await cp(join(FIXTURES, name), d, { recursive: true });
  const env = join(d, ".env");
  const content = await readFile(env, "utf8").catch(() => null);
  if (content !== null) await writeFile(env, content.replaceAll("__FAKE_STRIPE_KEY__", FAKE_STRIPE_KEY));
  git(d, "init", "-q", "-b", "main");
  if (commit) {
    git(d, "add", "-A");
    git(d, "commit", "-q", "-m", "fixture");
  }
  return d;
}

/**
 * Fausse clé Stripe des fixtures, assemblée à l'exécution : écrite d'un bloc, elle a le format d'une vraie clé et
 * la protection anti-fuite de GitHub refuse le dépôt. fixtureRepo l'écrit à la place de __FAKE_STRIPE_KEY__.
 */
export const FAKE_STRIPE_KEY = ["sk", "live", "FAKEdotationFIXTURE0000000000"].join("_");

/** Valeurs complètes des faux secrets des fixtures : elles ne doivent apparaître dans AUCUNE sortie. */
export const FAKE_SECRETS = [
  FAKE_STRIPE_KEY,
  "AKIAFAKEDOTATION0000",
  "ghp_FAKEdotationFixtureToken0000000000000",
  "sk-proj-FAKEdotationFixtureKey000000000000000000000000",
  "FakeFixtureDbPass99",
  "FakeFixturePass42",
  "fake-service-role-dotation-fixture",
  "fake-fixture-jwt-secret",
  "FakeDotationMcpToken0000",
];

/** PATH sans les outils externes : simule une machine où Gitleaks, Semgrep et OSV-Scanner sont absents. */
export function pathWithoutEngines(): string {
  // dirname : l'exécutable ne s'appelle pas toujours « node » (Fedora : /usr/bin/node-22).
  return ["/usr/bin", "/bin", dirname(process.execPath)].join(":");
}
