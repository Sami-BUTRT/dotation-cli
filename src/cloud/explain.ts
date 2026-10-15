// Assistant IA (offre Pro) : explication ou correctif d'un constat. L'extrait est masqué localement (secrets),
// puis par l'API ; la réponse arrive en flux (SSE).
import type { Finding } from "../core/finding.js";
import { redact } from "../core/redact.js";
import { CloudError, rawRequest } from "./client.js";

export interface SseEvent {
  event: string;
  data: string;
}

/** Lit un flux text/event-stream et produit ses événements. */
export async function* parseSse(body: ReadableStream<Uint8Array>): AsyncGenerator<SseEvent> {
  const decoder = new TextDecoder();
  let buf = "";
  for await (const chunk of body as unknown as AsyncIterable<Uint8Array>) {
    buf += decoder.decode(chunk, { stream: true });
    let idx = buf.indexOf("\n\n");
    while (idx >= 0) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let event = "message";
      const data: string[] = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      if (data.length) yield { event, data: data.join("\n") };
      idx = buf.indexOf("\n\n");
    }
  }
}

/** Extrait autour de la ligne (6 lignes avant et après), masqué, borné à 4 000 caractères. */
export function snippetAround(content: string, line: number): { text: string; masked: number } {
  const lines = content.split("\n");
  const start = Math.max(0, line - 7);
  const end = Math.min(lines.length, Math.max(line, 1) + 6);
  const r = redact(lines.slice(start, end).join("\n"));
  return { text: r.text.slice(0, 4000), masked: r.count };
}

export interface ExplainResult {
  maskedServer: number;
  inputTokens: number;
  outputTokens: number;
}

/** Envoie la demande et écrit le texte au fil de l'eau ; lève CloudError si l'API refuse ou si le flux échoue. */
export async function explain(
  base: string,
  token: string,
  args: { finding: Finding; snippet: string; fix: boolean },
  write: (s: string) => void,
): Promise<ExplainResult> {
  const res = await rawRequest(base, "/v1/ai/explain", {
    method: "POST",
    token,
    timeoutMs: 120_000,
    headers: { Accept: "text/event-stream" },
    json: {
      task: args.fix ? "fix" : "explain",
      lang: "en",
      finding: {
        ruleId: args.finding.id,
        severity: args.finding.severity,
        category: args.finding.category,
        file: args.finding.file,
      },
      snippet: args.snippet,
    },
  });
  if (!res.ok || !res.body) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    const retry = Number.parseInt(res.headers.get("Retry-After") ?? "", 10);
    throw new CloudError(
      res.status,
      p.code ?? `http_${res.status}`,
      p.detail ?? `HTTP ${res.status}`,
      Number.isFinite(retry) ? retry : undefined,
    );
  }
  const result: ExplainResult = { maskedServer: 0, inputTokens: 0, outputTokens: 0 };
  for await (const ev of parseSse(res.body)) {
    const data = JSON.parse(ev.data) as Record<string, unknown>;
    if (ev.event === "meta") result.maskedServer = Number(data.maskedSecrets ?? 0);
    else if (ev.event === "delta") write(String(data.text ?? ""));
    else if (ev.event === "done") {
      const u = (data.usage ?? {}) as { inputTokens?: number; outputTokens?: number };
      result.inputTokens = u.inputTokens ?? 0;
      result.outputTokens = u.outputTokens ?? 0;
      return result;
    } else if (ev.event === "error")
      throw new CloudError(502, String(data.code ?? "provider_error"), String(data.message ?? ""));
  }
  throw new CloudError(502, "stream_cut", "flux interrompu");
}
