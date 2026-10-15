// Service en ligne dotation.app (facultatif) : adresse de l'API et identifiants du CLI.
// Rien de ce module n'est utilisé par « dotation scan » sans --upload : un scan reste 100 % local.
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_API_URL = "https://api.dotation.app";

/** Adresse de l'API : DOTATION_API_URL, sinon l'adresse enregistrée à la connexion, sinon la production. */
export function apiUrl(env: NodeJS.ProcessEnv = process.env, saved?: string): string {
  const url = checkApiUrl(env.DOTATION_API_URL || saved || DEFAULT_API_URL);
  return url;
}

/** HTTPS obligatoire, sauf vers la machine locale (développement). Renvoie l'adresse sans barre finale. */
export function checkApiUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`invalid API address: ${raw}`);
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) {
    throw new Error(`API address refused (HTTPS required): ${raw}`);
  }
  if (u.username || u.password || u.search || u.hash) throw new Error(`invalid API address: ${raw}`);
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}

export interface Credentials {
  apiUrl: string;
  token: string;
  scopes: string[];
  createdAt: string;
  /** Plan vu au dernier `dotation whoami` (cache local, sert à l'en-tête). */
  plan?: string;
}

/** Fichier des identifiants : $XDG_CONFIG_HOME/dotation/credentials.json (dossier 700, fichier 600). */
export function credentialsPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.XDG_CONFIG_HOME || join(homedir(), ".config"), "dotation", "credentials.json");
}

const TOKEN_RE = /^dot_pat_[a-z2-7]{10}_[A-Za-z0-9_-]{43}$/;

export function isToken(s: string): boolean {
  return TOKEN_RE.test(s);
}

/** Identifiants : DOTATION_TOKEN (CI) a priorité sur le fichier. null si rien n'est configuré. */
export async function loadCredentials(env: NodeJS.ProcessEnv = process.env): Promise<Credentials | null> {
  if (env.DOTATION_TOKEN) {
    if (!isToken(env.DOTATION_TOKEN)) throw new Error("malformed DOTATION_TOKEN (expected dot_pat_…)");
    return { apiUrl: apiUrl(env), token: env.DOTATION_TOKEN, scopes: [], createdAt: "" };
  }
  let raw: string;
  try {
    raw = await readFile(credentialsPath(env), "utf8");
  } catch {
    return null;
  }
  const c = JSON.parse(raw) as Partial<Credentials>;
  if (typeof c.token !== "string" || !isToken(c.token))
    throw new Error(`identifiants illisibles : ${credentialsPath(env)}`);
  return {
    apiUrl: apiUrl(env, c.apiUrl),
    token: c.token,
    scopes: Array.isArray(c.scopes) ? c.scopes : [],
    createdAt: c.createdAt ?? "",
    ...(typeof c.plan === "string" ? { plan: c.plan } : {}),
  };
}

export async function saveCredentials(c: Credentials, env: NodeJS.ProcessEnv = process.env): Promise<string> {
  const path = credentialsPath(env);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(c, null, 2)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

export async function deleteCredentials(env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  try {
    await rm(credentialsPath(env));
    return true;
  } catch {
    return false;
  }
}
