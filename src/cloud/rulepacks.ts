// Packs de règles signés : téléchargés sur demande (« dotation rules update »), vérifiés (signature ed25519 avec
// une clé publique embarquée, empreinte de chaque fichier), installés dans le cache, puis lus hors ligne par « scan ».
import { createHash, createPublicKey, verify } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadRuleDir } from "../rules/loader.js";
import { CloudError, rawRequest, request } from "./client.js";

/**
 * Clés publiques de vérification embarquées (identifiant → clé ed25519 en base64). Un pack signé par une autre
 * clé n'est jamais installé. DOTATION_RULEPACK_PUBLIC_KEY en ajoute une (essais). Rotation : docs/runbook.md §6.
 */
export const EMBEDDED_KEYS: Readonly<Record<string, string>> = {
  // Clé de signature de production (générée le 2026-10-13 sur le poste du porteur ; la clé privée n'est jamais sur le serveur).
  c3302e3b7f3f1be9: "R/mGcpqFwHd1TF9Zfrpd3JUt6vXfj58qfev81cgPueE=",
};

export interface PackInfo {
  name: string;
  version: string;
  tier: "open" | "pro";
  sha256: string;
  keyId: string;
  available?: boolean;
}

interface Bundle {
  format: number;
  name: string;
  version: string;
  tier: string;
  files: { path: string; sha256: string; content: string }[];
}

export interface InstalledPack {
  name: string;
  version: string;
  tier: string;
  etag: string;
  keyId: string;
  installedAt: string;
}

export function packsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.XDG_CACHE_HOME || join(homedir(), ".cache"), "dotation", "rulepacks");
}

/** Identifiant d'une clé : 16 premiers caractères hexadécimaux du SHA-256 de la clé brute (comme l'API). */
export function keyId(raw: Buffer): string {
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

export function trustedKeys(env: NodeJS.ProcessEnv = process.env): Map<string, Buffer> {
  const keys = new Map<string, Buffer>();
  const add = (b64: string) => {
    const raw = Buffer.from(b64, "base64");
    if (raw.length === 32) keys.set(keyId(raw), raw);
  };
  for (const k of Object.values(EMBEDDED_KEYS)) add(k);
  if (env.DOTATION_RULEPACK_PUBLIC_KEY) add(env.DOTATION_RULEPACK_PUBLIC_KEY.trim());
  return keys;
}

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** Vérifie la signature détachée ed25519 des octets exacts du pack. */
export function verifySignature(raw: Buffer, data: Buffer, signatureB64: string): boolean {
  const sig = Buffer.from(signatureB64, "base64");
  if (sig.length !== 64) return false;
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, raw]), format: "der", type: "spki" });
  return verify(null, data, key, sig);
}

const NAME_RE = /^[a-z0-9][a-z0-9-]{1,48}$/;

/** Contrôle le contenu : en-tête attendu, chemins sûrs, empreinte de chaque fichier. */
export function checkBundle(data: Buffer, expect: Pick<PackInfo, "name" | "version" | "tier">): Bundle {
  const b = JSON.parse(data.toString("utf8")) as Bundle;
  if (
    b.format !== 1 ||
    b.name !== expect.name ||
    b.version !== expect.version ||
    b.tier !== expect.tier ||
    !Array.isArray(b.files)
  ) {
    throw new Error("unexpected pack header");
  }
  for (const f of b.files) {
    if (
      typeof f.path !== "string" ||
      f.path.startsWith("/") ||
      f.path.split("/").includes("..") ||
      !/\.ya?ml$/.test(f.path)
    ) {
      throw new Error(`path refused: ${String(f.path)}`);
    }
    if (createHash("sha256").update(f.content, "utf8").digest("hex") !== f.sha256)
      throw new Error(`hash mismatch: ${f.path}`);
  }
  return b;
}

export async function installedPacks(env: NodeJS.ProcessEnv = process.env): Promise<InstalledPack[]> {
  const dir = packsDir(env);
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const out: InstalledPack[] = [];
  for (const n of names.filter((x) => NAME_RE.test(x)).sort()) {
    try {
      out.push(JSON.parse(await readFile(join(dir, n, "pack.json"), "utf8")) as InstalledPack);
    } catch {
      /* pack incomplet : ignoré */
    }
  }
  return out;
}

/** Dossiers de règles des packs installés (lus par « scan », sans réseau). */
export async function installedPackDirs(env: NodeJS.ProcessEnv = process.env): Promise<string[]> {
  return (await installedPacks(env)).map((p) => join(packsDir(env), p.name));
}

export type UpdateOutcome =
  | { name: string; status: "installed" | "unchanged"; version: string }
  | { name: string; status: "locked" | "untrusted" | "invalid"; version: string; detail?: string };

/** Met à jour tous les packs disponibles pour l'appelant (jeton facultatif : sans jeton, les packs ouverts). */
export async function updatePacks(
  base: string,
  token: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Promise<UpdateOutcome[]> {
  const keys = trustedKeys(env);
  const { packs } = await request<{ packs: PackInfo[] }>(base, "/v1/rulepacks", { token });
  const installed = new Map((await installedPacks(env)).map((p) => [p.name, p]));
  const out: UpdateOutcome[] = [];
  for (const p of packs) {
    if (!NAME_RE.test(p.name)) continue;
    if (p.available === false) {
      out.push({ name: p.name, status: "locked", version: p.version });
      continue;
    }
    const key = keys.get(p.keyId);
    if (!key) {
      out.push({ name: p.name, status: "untrusted", version: p.version, detail: p.keyId });
      continue;
    }
    const prev = installed.get(p.name);
    const res = await rawRequest(base, `/v1/rulepacks/${p.name}`, {
      token,
      headers: prev?.etag ? { "If-None-Match": prev.etag } : {},
    });
    if (res.status === 304) {
      out.push({ name: p.name, status: "unchanged", version: prev?.version ?? p.version });
      continue;
    }
    if (!res.ok) throw new CloudError(res.status, `http_${res.status}`, `pack ${p.name} : HTTP ${res.status}`);
    const data = Buffer.from(await res.arrayBuffer());
    const sig = res.headers.get("X-Dotation-Signature") ?? "";
    if (res.headers.get("X-Dotation-Key-Id") !== p.keyId || !verifySignature(key, data, sig)) {
      out.push({ name: p.name, status: "invalid", version: p.version, detail: "signature" });
      continue;
    }
    try {
      const bundle = checkBundle(data, p);
      await install(bundle, res.headers.get("ETag") ?? "", p.keyId, env);
      out.push({ name: p.name, status: "installed", version: p.version });
    } catch (e) {
      out.push({
        name: p.name,
        status: "invalid",
        version: p.version,
        detail: e instanceof Error ? e.message : String(e),
      });
    }
  }
  return out;
}

/** Installation atomique : dossier temporaire, validation des règles, puis remplacement. */
async function install(b: Bundle, etag: string, kid: string, env: NodeJS.ProcessEnv) {
  const root = packsDir(env);
  const tmp = join(root, `.tmp-${b.name}-${process.pid}`);
  const dst = join(root, b.name);
  await rm(tmp, { recursive: true, force: true });
  await mkdir(tmp, { recursive: true, mode: 0o700 });
  try {
    for (const f of b.files) await writeFile(join(tmp, f.path.replace(/\//g, "__")), f.content, { mode: 0o600 });
    await loadRuleDir(tmp); // règles invalides : erreur, rien n'est installé
    const meta: InstalledPack = {
      name: b.name,
      version: b.version,
      tier: b.tier,
      etag,
      keyId: kid,
      installedAt: new Date().toISOString(),
    };
    await writeFile(join(tmp, "pack.json"), `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600 });
    await rm(dst, { recursive: true, force: true });
    await rename(tmp, dst);
  } catch (e) {
    await rm(tmp, { recursive: true, force: true });
    throw e;
  }
}
