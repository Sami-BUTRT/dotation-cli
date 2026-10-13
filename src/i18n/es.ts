import type { PartialMessages } from "./types.js";

// Parcial: lo que falta se muestra en inglés.
export const es: PartialMessages = {
  severity: { critical: "Crítico", high: "Alto", medium: "Medio", low: "Bajo" },
  report: {
    heading: "dotation: la higiene de tu código",
    target: (path, files) => `Analizado: ${path} (${files} archivo${files > 1 ? "s" : ""})`,
    clean: "Nada que señalar. Tu código parece limpio, ¡bien hecho!",
    score: (s) => `Puntuación de higiene: ${s}/100`,
    counts: (parts) => `Encontrado: ${parts}`,
    more: (n) => `… y ${n} más. Vuelve a lanzarlo con --all para verlo todo.`,
    why: "Por qué",
    fix: "Cómo corregirlo",
    engines: "Motores",
  },
};
