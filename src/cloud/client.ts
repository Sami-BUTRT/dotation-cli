// Client HTTP de l'API dotation.app : jeton Bearer, délais, erreurs RFC 9457 lues comme un code stable.
import { VERSION } from "../version.js";

export class CloudError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

export interface RequestOptions {
  method?: string;
  token?: string | undefined;
  json?: unknown;
  form?: Record<string, string>;
  headers?: Record<string, string>;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export function userAgent(): string {
  return `dotation-cli/${VERSION} (node ${process.versions.node}; ${process.platform})`;
}

/** Requête brute (réponse non lue) : pour les flux SSE et les ETag. */
export async function rawRequest(base: string, path: string, opts: RequestOptions = {}): Promise<Response> {
  const headers: Record<string, string> = { "User-Agent": userAgent(), Accept: "application/json", ...opts.headers };
  let body: string | undefined;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  } else if (opts.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(opts.form).toString();
  }
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const timeout = AbortSignal.timeout(opts.timeoutMs ?? 30_000);
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
  try {
    const init: RequestInit = { method: opts.method ?? "GET", headers, signal, redirect: "error" };
    if (body !== undefined) init.body = body;
    return await fetch(`${base}${path}`, init);
  } catch (e) {
    const reason = e instanceof Error && e.name === "TimeoutError" ? "timed out" : "unreachable";
    throw new CloudError(0, "network", `${base} ${reason}`);
  }
}

/** Requête JSON : renvoie le corps décodé, ou lève CloudError (statut, code de l'API, message). */
export async function request<T>(base: string, path: string, opts: RequestOptions = {}): Promise<T> {
  // Les erreurs de l'API (problem+json ou OAuth) deviennent des CloudError au code stable.
  const res = await rawRequest(base, path, opts);
  const text = await res.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = undefined;
  }
  if (!res.ok) {
    const p = (data ?? {}) as { code?: string; error?: string; detail?: string };
    const retry = Number.parseInt(res.headers.get("Retry-After") ?? "", 10);
    throw new CloudError(
      res.status,
      p.code ?? p.error ?? `http_${res.status}`,
      p.detail ?? p.error ?? `HTTP ${res.status}`,
      Number.isFinite(retry) ? retry : undefined,
    );
  }
  return data as T;
}
