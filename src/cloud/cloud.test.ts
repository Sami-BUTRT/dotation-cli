import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hasCommand } from "../core/exec.js";
import type { Finding } from "../core/finding.js";
import { MASK, redact } from "../core/redact.js";
import type { ScanReport } from "../scan.js";
import { scan } from "../scan.js";
import { FIXTURES, tempDir } from "../test/helpers.js";
import { CloudError, request } from "./client.js";
import { checkApiUrl, credentialsPath, loadCredentials, saveCredentials } from "./config.js";
import { type DeviceStart, pollDevice } from "./device.js";
import { explain, parseSse, snippetAround } from "./explain.js";
import { checkBundle, EMBEDDED_KEYS, installedPacks, keyId, updatePacks } from "./rulepacks.js";
import { buildPayload, fingerprint, upload } from "./upload.js";

type Handler = (req: IncomingMessage, res: ServerResponse, body: string) => void;
const servers: { close: () => void }[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

/** Faux serveur d'API sur 127.0.0.1 (port éphémère). */
async function fakeApi(handler: Handler): Promise<string> {
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => handler(req, res, body));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  servers.push({ close: () => srv.close() });
  return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

const TOKEN = `dot_pat_abcdefghij_${"A".repeat(43)}`;

describe("configuration", () => {
  it("HTTPS obligatoire, sauf vers la machine locale", () => {
    expect(checkApiUrl("https://api.dotation.app/")).toBe("https://api.dotation.app");
    expect(checkApiUrl("http://localhost:8088/api")).toBe("http://localhost:8088/api");
    for (const bad of [
      "http://api.dotation.app",
      "ftp://x",
      "https://u:p@api.dotation.app",
      "https://api.dotation.app?x=1",
      "pas une url",
    ]) {
      expect(() => checkApiUrl(bad)).toThrow();
    }
  });

  it("identifiants : fichier en 600, dossier en 700, DOTATION_TOKEN prioritaire", async () => {
    const env = { XDG_CONFIG_HOME: await tempDir() } as NodeJS.ProcessEnv;
    expect(await loadCredentials(env)).toBeNull();
    const path = await saveCredentials(
      { apiUrl: "https://api.dotation.app", token: TOKEN, scopes: ["scans:write"], createdAt: "x" },
      env,
    );
    expect(path).toBe(credentialsPath(env));
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(join(path, ".."))).mode & 0o777).toBe(0o700);
    expect((await loadCredentials(env))?.token).toBe(TOKEN);
    const other = `dot_pat_zyxwvutsrq_${"B".repeat(43)}`;
    expect((await loadCredentials({ ...env, DOTATION_TOKEN: other }))?.token).toBe(other);
    await expect(loadCredentials({ ...env, DOTATION_TOKEN: "n'importe quoi" })).rejects.toThrow();
  });
});

describe("connexion par code (RFC 8628)", () => {
  const start: DeviceStart = {
    device_code: "d".repeat(43),
    user_code: "BCDF-GHJK",
    verification_uri: "x",
    expires_in: 900,
    interval: 5,
  };

  it("attend, ralentit sur slow_down, puis récupère le jeton", async () => {
    const answers = ["authorization_pending", "slow_down", "authorization_pending"];
    let form = "";
    const base = await fakeApi((_req, res, body) => {
      form = body;
      const next = answers.shift();
      if (next) json(res, 400, { error: next });
      else json(res, 200, { access_token: TOKEN, token_type: "Bearer", scope: "scans:write" });
    });
    const waits: number[] = [];
    let now = 0;
    const tok = await pollDevice(base, start, {
      sleep: async (ms) => {
        waits.push(ms);
        now += ms;
      },
      now: () => now,
    });
    expect(tok.access_token).toBe(TOKEN);
    expect(waits).toEqual([5000, 5000, 10000, 10000]);
    expect(new URLSearchParams(form).get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:device_code");
  });

  it("refus et expiration", async () => {
    const base = await fakeApi((_req, res) => json(res, 400, { error: "access_denied" }));
    await expect(pollDevice(base, start, { sleep: async () => {}, now: () => 0 })).rejects.toMatchObject({
      code: "access_denied",
    });
    const pending = await fakeApi((_req, res) => json(res, 400, { error: "authorization_pending" }));
    let now = 0;
    await expect(
      pollDevice(
        pending,
        { ...start, expires_in: 12 },
        {
          sleep: async (ms) => {
            now += ms;
          },
          now: () => now,
        },
      ),
    ).rejects.toMatchObject({
      code: "expired_token",
    });
  });
});

function report(findings: Partial<Finding>[]): ScanReport {
  return {
    root: "/home/moi/mon-app",
    target: ".",
    lang: "fr",
    fileCount: 3,
    score: 61,
    statuses: [],
    findings: findings.map((f) => ({
      id: "DOT-SEC-001",
      engine: "house",
      severity: "critical",
      category: "secret",
      title: "Clé d'API écrite en dur",
      explanation: "…",
      fix: "…",
      file: "lib/config.ts",
      line: 3,
      snippet: 'const k = "sk_live_****abcd";',
      ...f,
    })) as Finding[],
  };
}

describe("envoi d'un rapport", () => {
  it("métadonnées seulement : aucun extrait, titre ni explication ; empreinte indépendante de la ligne", async () => {
    const p = buildPayload(
      report([
        {},
        { line: 40 },
        { id: "osv:GHSA-x", category: "dependency", severity: "high", file: "package-lock.json", line: 0, snippet: "" },
      ]),
    );
    expect(p.project).toBe("mon-app");
    expect(p.findings).toHaveLength(2); // même règle, même fichier, même contenu : un seul constat (déplacé)
    for (const f of p.findings)
      expect(Object.keys(f).sort()).toEqual(["category", "file", "fingerprint", "line", "ruleId", "severity"]);
    const text = JSON.stringify(p);
    for (const leak of ["sk_live", "const k", "Clé d'API", "/home/moi"]) expect(text).not.toContain(leak);
    expect(fingerprint({ id: "R", file: "a", snippet: "x  =  1" })).toBe(
      fingerprint({ id: "R", file: "a", snippet: " x = 1 " }),
    );
    const hashed = buildPayload(report([{}]), { hashPaths: true, project: "démo\nprojet" });
    expect(hashed.findings[0]?.file).toBe(`sha256:${createHash("sha256").update("lib/config.ts").digest("hex")}`);
    expect(hashed.project).toBe("démoprojet");
  });

  it("envoie avec le jeton et lit la réponse ; erreurs de l'API en codes stables", async () => {
    let auth = "";
    let got: unknown;
    const base = await fakeApi((req, res, body) => {
      auth = req.headers.authorization ?? "";
      got = JSON.parse(body);
      if (req.headers["user-agent"]?.startsWith("dotation-cli/"))
        json(res, 201, { reportId: 1, projectId: 2, findings: 1, new: 1, fixed: 0 });
      else json(res, 400, {});
    });
    const r = await upload(base, TOKEN, buildPayload(report([{}])));
    expect(r.new).toBe(1);
    expect(auth).toBe(`Bearer ${TOKEN}`);
    expect((got as { findings: unknown[] }).findings).toHaveLength(1);
    const denied = await fakeApi((_req, res) => json(res, 403, { code: "plan_required", detail: "Pro" }));
    await expect(upload(denied, TOKEN, buildPayload(report([{}])))).rejects.toMatchObject({
      status: 403,
      code: "plan_required",
    });
    const limited = await fakeApi((_req, res) => json(res, 429, { code: "rate_limited" }, { "Retry-After": "42" }));
    await expect(request(limited, "/v1/me")).rejects.toMatchObject({ status: 429, retryAfter: 42 });
    await expect(request("http://127.0.0.1:1", "/v1/me")).rejects.toBeInstanceOf(CloudError);
  });
});

const PACK_RULE = `- id: PACK-TEST-001
  severity: medium
  category: config
  detector:
    type: regex
    files: ["**/*.txt"]
    pattern: 'DOTATION_PACK_MARKER'
  text:
    fr: { title: Marqueur de pack, explanation: Règle venue d'un pack signé., fix: Rien à corriger. }
    en: { title: Pack marker, explanation: Rule from a signed pack., fix: Nothing to fix. }
`;

function makeBundle(name: string, version: string, tier: string, content = PACK_RULE) {
  const sha = createHash("sha256").update(content, "utf8").digest("hex");
  return Buffer.from(
    JSON.stringify({
      format: 1,
      name,
      version,
      tier,
      createdAt: "2026-10-12T00:00:00Z",
      files: [{ path: "rules/test.yaml", sha256: sha, content }],
    }),
  );
}

describe("packs de règles signés", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  const kid = keyId(raw);
  const other = generateKeyPairSync("ed25519");

  async function packServer(
    bundle: Buffer,
    opts: { sigKey?: typeof privateKey; listKey?: string; available?: boolean } = {},
  ) {
    const etag = `"${createHash("sha256").update(bundle).digest("hex")}"`;
    const seen: (string | undefined)[] = [];
    const base = await fakeApi((req, res) => {
      if (req.url === "/v1/rulepacks") {
        json(res, 200, {
          packs: [
            {
              name: "socle",
              version: "1.0.0",
              tier: "open",
              sha256: etag.slice(1, -1),
              keyId: opts.listKey ?? kid,
              available: opts.available ?? true,
            },
          ],
        });
        return;
      }
      seen.push(req.headers["if-none-match"]);
      if (req.headers["if-none-match"] === etag) {
        res.writeHead(304).end();
        return;
      }
      res.writeHead(200, {
        "Content-Type": "application/json",
        ETag: etag,
        "X-Dotation-Key-Id": opts.listKey ?? kid,
        "X-Dotation-Signature": sign(null, bundle, opts.sigKey ?? privateKey).toString("base64"),
      });
      res.end(bundle);
    });
    return { base, seen };
  }

  async function env() {
    return {
      XDG_CACHE_HOME: await tempDir(),
      DOTATION_RULEPACK_PUBLIC_KEY: raw.toString("base64"),
    } as NodeJS.ProcessEnv;
  }

  it("installe un pack signé, puis 304 tant qu'il ne change pas ; le scan l'utilise hors ligne", async () => {
    const e = await env();
    const { base, seen } = await packServer(makeBundle("socle", "1.0.0", "open"));
    expect(await updatePacks(base, undefined, e)).toEqual([{ name: "socle", status: "installed", version: "1.0.0" }]);
    expect(await updatePacks(base, undefined, e)).toEqual([{ name: "socle", status: "unchanged", version: "1.0.0" }]);
    expect(seen[1]).toMatch(/^"[0-9a-f]{64}"$/);
    const installed = await installedPacks(e);
    expect(installed.map((p) => [p.name, p.keyId])).toEqual([["socle", kid]]);
    // Le scan lit le cache : la règle du pack trouve son marqueur.
    const dir = await tempDir();
    await writeFile(join(dir, "notes.txt"), "DOTATION_PACK_MARKER\n");
    const prev = process.env.XDG_CACHE_HOME;
    process.env.XDG_CACHE_HOME = e.XDG_CACHE_HOME;
    try {
      const r = await scan(dir, { lang: "fr" });
      expect(r.findings.some((f) => f.id === "PACK-TEST-001")).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.XDG_CACHE_HOME;
      else process.env.XDG_CACHE_HOME = prev;
    }
  });

  it("refuse une signature fausse, une clé inconnue, un pack réservé, des règles invalides", async () => {
    const e = await env();
    const forged = await packServer(makeBundle("socle", "1.0.0", "open"), { sigKey: other.privateKey });
    expect((await updatePacks(forged.base, undefined, e))[0]).toMatchObject({ status: "invalid", detail: "signature" });
    const unknown = await packServer(makeBundle("socle", "1.0.0", "open"), { listKey: "0123456789abcdef" });
    expect((await updatePacks(unknown.base, undefined, e))[0]?.status).toBe("untrusted");
    const locked = await packServer(makeBundle("socle", "1.0.0", "open"), { available: false });
    expect((await updatePacks(locked.base, undefined, e))[0]?.status).toBe("locked");
    const broken = await packServer(makeBundle("socle", "1.0.0", "open", "- id: X\n  pas une règle\n"));
    expect((await updatePacks(broken.base, undefined, e))[0]?.status).toBe("invalid");
    expect(await installedPacks(e)).toEqual([]);
    // Sans clé de confiance du tout : rien n'est installé.
    const bare = { XDG_CACHE_HOME: e.XDG_CACHE_HOME } as NodeJS.ProcessEnv;
    const ok = await packServer(makeBundle("socle", "1.0.0", "open"));
    expect((await updatePacks(ok.base, undefined, bare))[0]?.status).toBe("untrusted");
  });

  it("clés embarquées : chaque identifiant correspond à sa clé de 32 octets", () => {
    const entries = Object.entries(EMBEDDED_KEYS);
    expect(entries.length).toBeGreaterThan(0);
    for (const [id, b64] of entries) {
      const raw = Buffer.from(b64, "base64");
      expect(raw).toHaveLength(32);
      expect(keyId(raw)).toBe(id);
    }
  });

  it("contrôle du contenu : en-tête, chemins, empreintes", () => {
    const good = makeBundle("socle", "1.0.0", "open");
    expect(checkBundle(good, { name: "socle", version: "1.0.0", tier: "open" }).files).toHaveLength(1);
    expect(() => checkBundle(good, { name: "autre", version: "1.0.0", tier: "open" })).toThrow();
    const evil = Buffer.from(good.toString().replace("rules/test.yaml", "../../.bashrc.yaml"));
    expect(() => checkBundle(evil, { name: "socle", version: "1.0.0", tier: "open" })).toThrow(/path refused/);
    const tampered = Buffer.from(good.toString().replace("DOTATION_PACK_MARKER", "AUTRE_MARQUEUR"));
    expect(() => checkBundle(tampered, { name: "socle", version: "1.0.0", tier: "open" })).toThrow(/hash mismatch/);
  });
});

describe("assistant IA", () => {
  it("masque les secrets des fixtures avant envoi", async () => {
    const cfg = await readFile(join(FIXTURES, "vulnerable-app", "lib", "config.ts"), "utf8");
    const key = await readFile(join(FIXTURES, "vulnerable-app", "keys", "server.pem"), "utf8");
    const r = redact(`${cfg}\n${key}`);
    for (const leak of ["AKIAFAKEDOTATION0000", "ghp_FAKEdotation", "sk-proj-FAKEdotation", "BEGIN RSA PRIVATE KEY"])
      expect(r.text).not.toContain(leak);
    expect(r.count).toBeGreaterThanOrEqual(4);
    expect(r.text).toContain("export const awsAccessKeyId");
    expect(redact("const user = await db.select().from(users);").count).toBe(0);
    expect(redact(`password = "${"x".repeat(12)}"`).text).toBe(`password = "${MASK}"`);
  });

  it("extrait autour de la ligne, masqué", () => {
    const lines = Array.from({ length: 30 }, (_, i) => `ligne ${i + 1}`);
    lines[14] = `token: "${"s".repeat(20)}"`;
    const s = snippetAround(lines.join("\n"), 15);
    expect(s.text.split("\n")).toHaveLength(13);
    expect(s.text).toContain("ligne 9");
    expect(s.masked).toBe(1);
    expect(s.text).not.toContain("s".repeat(20));
  });

  it("lit un flux SSE découpé n'importe où", async () => {
    const raw =
      'event: meta\ndata: {"maskedSecrets":2}\n\nevent: delta\ndata: {"text":"Bon"}\n\nevent: delta\ndata: {"text":"jour"}\n\nevent: done\ndata: {"usage":{"inputTokens":3,"outputTokens":2}}\n\n';
    const chunks = [raw.slice(0, 7), raw.slice(7, 40), raw.slice(40, 41), raw.slice(41)];
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (const ch of chunks) c.enqueue(new TextEncoder().encode(ch));
        c.close();
      },
    });
    const events = [];
    for await (const e of parseSse(stream)) events.push(e.event);
    expect(events).toEqual(["meta", "delta", "delta", "done"]);
  });

  it("appel complet : texte au fil de l'eau ; offre et disponibilité", async () => {
    let sent: Record<string, unknown> = {};
    const base = await fakeApi((_req, res, body) => {
      sent = JSON.parse(body);
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write('event: meta\ndata: {"maskedSecrets":0}\n\n');
      res.write('event: delta\ndata: {"text":"Active "}\n\n');
      res.write('event: delta\ndata: {"text":"RLS."}\n\n');
      res.end('event: done\ndata: {"usage":{"inputTokens":10,"outputTokens":2}}\n\n');
    });
    let out = "";
    const finding = report([{}]).findings[0] as Finding;
    const r = await explain(base, TOKEN, { finding, snippet: "x", fix: true, lang: "fr" }, (s) => (out += s));
    expect(out).toBe("Active RLS.");
    expect(r.outputTokens).toBe(2);
    expect(sent).toMatchObject({
      task: "fix",
      lang: "fr",
      finding: { ruleId: "DOT-SEC-001", severity: "critical", category: "secret" },
      snippet: "x",
    });
    expect(Object.keys(sent.finding as object).sort()).toEqual(["category", "file", "ruleId", "severity"]);
    const closed = await fakeApi((_req, res) => json(res, 503, { code: "ai_unavailable" }));
    await expect(
      explain(closed, TOKEN, { finding, snippet: "", fix: false, lang: "en" }, () => {}),
    ).rejects.toMatchObject({ code: "ai_unavailable" });
  });
});

// La promesse tient même connecté et avec des packs installés : « scan » sans --upload n'ouvre aucune connexion.
describe.runIf((await hasCommand("strace", ["-V"])) && process.platform === "linux")(
  "scan connecté, toujours hors ligne",
  () => {
    it("aucune connexion réseau pendant un scan, identifiants et packs présents", async () => {
      const { execFile } = await import("node:child_process");
      const { packagePath } = await import("../paths.js");
      const home = await tempDir();
      await saveCredentials({ apiUrl: "https://api.dotation.app", token: TOKEN, scopes: [], createdAt: "" }, {
        XDG_CONFIG_HOME: home,
      } as NodeJS.ProcessEnv);
      const dir = await tempDir();
      await writeFile(join(dir, "notes.txt"), "rien\n");
      const trace = join(await tempDir(), "trace.txt");
      await new Promise<void>((resolve) => {
        execFile(
          "strace",
          [
            "-f",
            "-qq",
            "-e",
            "trace=connect",
            "-o",
            trace,
            process.execPath,
            packagePath("dist/cli.js"),
            "scan",
            dir,
            "--format",
            "json",
          ],
          { env: { ...process.env, XDG_CONFIG_HOME: home } },
          () => resolve(),
        );
      });
      const lines = (await readFile(trace, "utf8")).split("\n").filter((l) => /AF_INET6?/.test(l));
      expect(lines.filter((l) => !/127\.0\.0\.|"::1"|inet_addr\("0\.0\.0\.0"\)/.test(l))).toEqual([]);
    });
  },
);
