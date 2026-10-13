// Masquage de secrets dans un texte quelconque (extrait envoyé à l'assistant IA). Même liste que l'API
// (api/internal/ai/redact.go) : le code est masqué AVANT de quitter la machine, puis une seconde fois côté serveur.

// Commence par « [SECRET » comme le masque de l'API : le serveur reconnaît un extrait déjà masqué et ne le recompte pas.
export const MASK = "[SECRET REDACTED]";

const PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g,
  /\bwhsec_[A-Za-z0-9]{10,}\b/g,
  /\bsk-ant-[A-Za-z0-9_-]{10,}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
  /\bdot_pat_[a-z2-7]{10}_[A-Za-z0-9_-]{43}\b/g,
  /\bsb_secret_[A-Za-z0-9_-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
];
const URL_CREDS = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^\s:/@]+:[^\s/@]+@/g;
const ASSIGN =
  /((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_]*["']?\s*(?:=|:|:=|=>)\s*)(["'`]?)[^\s"'`,;)]{6,}(["'`]?)/gi;

/** Remplace chaque secret reconnu par MASK ; renvoie le texte et le nombre de remplacements. */
export function redact(text: string): { text: string; count: number } {
  let count = 0;
  let out = text;
  for (const re of PATTERNS) {
    out = out.replace(re, () => {
      count++;
      return MASK;
    });
  }
  out = out.replace(URL_CREDS, (_m, scheme: string) => {
    count++;
    return `${scheme}${MASK}@`;
  });
  out = out.replace(ASSIGN, (m, head: string, q1: string, q2: string) => {
    if (m.includes(MASK.slice(0, 7))) return m;
    count++;
    return `${head}${q1}${MASK}${q2}`;
  });
  return { text: out, count };
}
