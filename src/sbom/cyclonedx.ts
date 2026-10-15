// SBOM CycloneDX 1.6 (JSON) construit à partir des lockfiles du projet, sans réseau ni installation.
// OWASP A03:2025 (visibilité des dépendances) et Software Component Verification Standard (SCVS).
import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import { parse as parseYaml } from "yaml";
import { collectFiles } from "../core/files.js";
import { stripJsonComments } from "../rules/detectors.js";
import { VERSION } from "../version.js";

export interface Component {
  ecosystem: "npm" | "pypi" | "cargo" | "golang";
  name: string;
  version: string;
  /** Lockfile d'où vient le composant (relatif à la racine). */
  source: string;
  /** Empreinte publiée par le registre, quand le lockfile la donne. */
  hash?: { alg: "SHA-512" | "SHA-256" | "SHA-1"; content: string } | undefined;
  dev?: boolean | undefined;
}

/** Lockfiles reconnus (nom de fichier, à n'importe quel niveau du projet). */
const PARSERS: Record<string, (text: string, source: string) => Component[]> = {
  "package-lock.json": parseNpmLock,
  "npm-shrinkwrap.json": parseNpmLock,
  "pnpm-lock.yaml": parsePnpmLock,
  "yarn.lock": parseYarnLock,
  "bun.lock": parseBunLock,
  "requirements.txt": parseRequirements,
  "poetry.lock": (t, s) => parseTomlPackages(t, s, "pypi"),
  "uv.lock": (t, s) => parseTomlPackages(t, s, "pypi"),
  "Cargo.lock": (t, s) => parseTomlPackages(t, s, "cargo"),
  "go.mod": parseGoMod,
};

/** « sha512-<base64> » (npm) en empreinte hexadécimale CycloneDX. */
function integrityHash(integrity: unknown): Component["hash"] {
  if (typeof integrity !== "string") return undefined;
  const m = /^(sha512|sha256|sha1)-([A-Za-z0-9+/=]+)/.exec(integrity.split(/\s+/)[0] ?? "");
  if (!m) return undefined;
  const alg = ({ sha512: "SHA-512", sha256: "SHA-256", sha1: "SHA-1" } as const)[m[1] as "sha512" | "sha256" | "sha1"];
  return { alg, content: Buffer.from(m[2] as string, "base64").toString("hex") };
}

/** Sépare « @scope/nom@1.2.3 » ou « nom@1.2.3(peer@x) » en nom et version. */
function splitSpec(spec: string): { name: string; version: string } | null {
  const clean = spec.replace(/^\//, "").replace(/\(.*$/, "");
  const at = clean.lastIndexOf("@");
  if (at <= 0) return null;
  const version = clean.slice(at + 1).replace(/^npm:/, "");
  return /^\d/.test(version) ? { name: clean.slice(0, at), version } : null;
}

export function parseNpmLock(text: string, source: string): Component[] {
  const doc = JSON.parse(text) as {
    packages?: Record<string, { version?: string; integrity?: string; dev?: boolean; link?: boolean; name?: string }>;
    dependencies?: Record<string, NpmV1Dep>;
  };
  const out: Component[] = [];
  if (doc.packages) {
    for (const [path, p] of Object.entries(doc.packages)) {
      if (!path || p.link || !p.version) continue;
      const name = p.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ ecosystem: "npm", name, version: p.version, source, hash: integrityHash(p.integrity), dev: p.dev });
    }
    return out;
  }
  const walk = (deps: Record<string, NpmV1Dep> | undefined) => {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (d.version && /^\d/.test(d.version))
        out.push({ ecosystem: "npm", name, version: d.version, source, hash: integrityHash(d.integrity), dev: d.dev });
      walk(d.dependencies);
    }
  };
  walk(doc.dependencies);
  return out;
}
interface NpmV1Dep {
  version?: string;
  integrity?: string;
  dev?: boolean;
  dependencies?: Record<string, NpmV1Dep>;
}

export function parsePnpmLock(text: string, source: string): Component[] {
  const doc = (parseYaml(text) ?? {}) as {
    packages?: Record<string, { resolution?: { integrity?: string }; dev?: boolean }>;
  };
  const out: Component[] = [];
  for (const [key, p] of Object.entries(doc.packages ?? {})) {
    const s = splitSpec(key);
    if (s) out.push({ ecosystem: "npm", ...s, source, hash: integrityHash(p?.resolution?.integrity), dev: p?.dev });
  }
  return out;
}

/** yarn.lock v1 (« version "1.2.3" ») et Berry (« version: 1.2.3 »). */
export function parseYarnLock(text: string, source: string): Component[] {
  const out: Component[] = [];
  for (const block of text.split(/\n(?=\S)/)) {
    const header = block.split("\n")[0] ?? "";
    if (header.startsWith("#") || header.startsWith("__metadata") || !header.endsWith(":")) continue;
    const first = header.replace(/:$/, "").split(",")[0]?.trim().replace(/^"|"$/g, "") ?? "";
    const at = first.indexOf("@", first.startsWith("@") ? 1 : 0);
    const name = at > 0 ? first.slice(0, at) : first;
    const version = /^\s+version:?\s+"?([^"\s]+)"?/m.exec(block)?.[1];
    if (!name || !version || /^0\.0\.0-use\.local$/.test(version)) continue;
    const integrity = /^\s+integrity:?\s+"?([^"\s]+)"?/m.exec(block)?.[1];
    out.push({ ecosystem: "npm", name, version, source, hash: integrityHash(integrity) });
  }
  return out;
}

/** bun.lock : JSON avec virgules finales ; packages = { nom: ["nom@1.2.3", registre, {…}, "sha512-…"] }. */
export function parseBunLock(text: string, source: string): Component[] {
  const doc = JSON.parse(stripJsonComments(text)) as { packages?: Record<string, unknown[]> };
  const out: Component[] = [];
  for (const entry of Object.values(doc.packages ?? {})) {
    const s = typeof entry[0] === "string" ? splitSpec(entry[0]) : null;
    if (s) out.push({ ecosystem: "npm", ...s, source, hash: integrityHash(entry[3]) });
  }
  return out;
}

/** Seulement les lignes figées (« paquet==1.2.3 ») : une plage ne désigne pas un composant précis. */
export function parseRequirements(text: string, source: string): Component[] {
  const out: Component[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const m = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*===?\s*([\w.+!-]+)/.exec(raw.trim());
    if (m) out.push({ ecosystem: "pypi", name: m[1] as string, version: m[2] as string, source });
  }
  return out;
}

/** poetry.lock, uv.lock, Cargo.lock : blocs [[package]] avec name = "…" et version = "…". */
export function parseTomlPackages(text: string, source: string, ecosystem: "pypi" | "cargo"): Component[] {
  const out: Component[] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package)/m)[0] ?? "";
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    // uv.lock : le projet lui-même porte « source = { editable = "." } » ou « virtual ».
    if (!name || !version || /^source\s*=\s*\{\s*(?:editable|virtual)\b/m.test(body)) continue;
    out.push({ ecosystem, name, version, source });
  }
  return out;
}

export function parseGoMod(text: string, source: string): Component[] {
  const out: Component[] = [];
  const add = (line: string) => {
    const m = /^\s*([\w.~/-]+\.[\w.~/-]+)\s+(v[\w.+-]+)/.exec(line);
    if (m) out.push({ ecosystem: "golang", name: m[1] as string, version: m[2] as string, source });
  };
  for (const block of text.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) (block[1] ?? "").split("\n").forEach(add);
  for (const m of text.matchAll(/^require\s+([^(\n].*)$/gm)) add(m[1] as string);
  return out;
}

/** Package URL (https://github.com/package-url/purl-spec). */
export function purl(c: Component): string {
  const enc = (s: string) => encodeURIComponent(s).replace(/%2F/g, "/");
  if (c.ecosystem === "npm") {
    const [scope, name] = c.name.startsWith("@") ? c.name.split("/") : [undefined, c.name];
    return `pkg:npm/${scope ? `${enc(scope)}/` : ""}${enc(name ?? "")}@${enc(c.version)}`;
  }
  if (c.ecosystem === "pypi") return `pkg:pypi/${enc(c.name.toLowerCase().replace(/[_.]+/g, "-"))}@${enc(c.version)}`;
  if (c.ecosystem === "golang") return `pkg:golang/${enc(c.name)}@${enc(c.version)}`;
  return `pkg:cargo/${enc(c.name)}@${enc(c.version)}`;
}

/** Lit tous les lockfiles du projet (fichiers ignorés par git exclus) et renvoie les composants, sans doublon. */
export async function collectComponents(root: string): Promise<Component[]> {
  const fileSet = await collectFiles(root, { scope: "project", staged: false, excludes: [] });
  const byPurl = new Map<string, Component>();
  for (const f of fileSet.files) {
    const parser = PARSERS[basename(f.path)];
    if (!parser) continue;
    const text = await f.read();
    if (text === null) continue;
    let found: Component[];
    try {
      found = parser(text, f.path);
    } catch {
      continue; // lockfile illisible : on ne l'invente pas
    }
    for (const c of found) {
      const key = purl(c);
      const cur = byPurl.get(key);
      if (!cur) byPurl.set(key, c);
      else if (!cur.hash && c.hash) cur.hash = c.hash;
      else if (cur.dev && !c.dev) cur.dev = false;
    }
  }
  return [...byPurl.values()].sort((a, b) => purl(a).localeCompare(purl(b)));
}

export interface BomOptions {
  /** Pour des sorties reproductibles (tests). */
  serial?: string;
  timestamp?: string;
}

export function toCycloneDx(name: string, components: readonly Component[], opts: BomOptions = {}) {
  return {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${opts.serial ?? randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools: { components: [{ type: "application", name: "dotation", version: VERSION }] },
      component: { type: "application", name, "bom-ref": `app:${name}` },
    },
    components: components.map((c) => {
      const ref = purl(c);
      return {
        type: "library",
        "bom-ref": ref,
        name: c.name,
        version: c.version,
        purl: ref,
        ...(c.hash ? { hashes: [{ alg: c.hash.alg, content: c.hash.content }] } : {}),
        properties: [
          { name: "dotation:source", value: c.source },
          ...(c.dev ? [{ name: "cdx:npm:package:development", value: "true" }] : []),
        ],
      };
    }),
  };
}
