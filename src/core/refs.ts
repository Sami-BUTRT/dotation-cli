// Références de sécurité attachées à un constat : catégories OWASP (Top 10 2025, API 2023, LLM 2025, MCP 2025,
// NHI 2025, CI/CD) et CWE. Elles apparaissent dans la sortie texte, le JSON, le SARIF et le serveur MCP.

/** Formats acceptés, du plus courant au plus spécialisé. */
export const REF_PATTERN =
  /^(?:A(?:0[1-9]|10):2025|API(?:[1-9]|10):2023|LLM(?:0[1-9]|10):2025|MCP(?:0[1-9]|10):2025|NHI(?:[1-9]|10):2025|CICD-SEC-(?:[1-9]|10)|CWE-[1-9]\d{0,4})$/;

export function isRef(s: string): boolean {
  return REF_PATTERN.test(s);
}

/** Page officielle de la référence (liste du référentiel ; page exacte pour une CWE). */
export function refUrl(ref: string): string {
  if (ref.startsWith("CWE-")) return `https://cwe.mitre.org/data/definitions/${ref.slice(4)}.html`;
  if (ref.startsWith("API")) return "https://api-security.owasp.org/editions/2023/en/0x11-t10";
  if (ref.startsWith("LLM")) return "https://genai.owasp.org/llm-top-10/";
  if (ref.startsWith("MCP")) return "https://owasp.org/www-project-mcp-top-10/";
  if (ref.startsWith("NHI")) return "https://owasp.org/www-project-non-human-identities-top-10/2025/";
  if (ref.startsWith("CICD")) return "https://owasp.org/www-project-top-10-ci-cd-security-risks/";
  return "https://top10.owasp.org/2025";
}

/** Étiquette SARIF reconnue par GitHub Code Scanning pour une CWE (« external/cwe/cwe-079 »). */
export function sarifTag(ref: string): string {
  return ref.startsWith("CWE-") ? `external/cwe/cwe-${ref.slice(4).padStart(3, "0")}` : `owasp/${ref}`;
}

/** Références fixes des moteurs externes. */
export const ENGINE_REFS = {
  gitleaks: ["A07:2025", "NHI2:2025", "CWE-798"],
  osv: ["A03:2025", "CWE-1395"],
} as const;
