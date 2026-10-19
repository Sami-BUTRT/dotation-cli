// Symbole « Le saut » de la charte (disque ciel, arc et point abricot), même géométrie que web/public/symbol.svg
// (viewBox 0 29.5 103 68.5) : disque (28,70) r 22, point (88,70) r 9, arc de centre (58,70), rayon 30, épaisseur 9.

export type Ink = "sky" | "apricot";

export const SYMBOL = {
  viewBox: [0, 29.5, 103, 68.5],
  disc: { cx: 28, cy: 70, r: 22 },
  dot: { cx: 88, cy: 70, r: 9 },
  arc: { cx: 58, cy: 70, r: 30, width: 9 },
} as const;

/** Couleur du pixel de centre (x, y) d'une grille cols × rows, ou rien (fond). Le disque passe devant l'arc. */
export function inkAt(x: number, y: number, cols: number, rows: number): Ink | undefined {
  const [vx, vy, vw, vh] = SYMBOL.viewBox;
  const X = vx + ((x + 0.5) / cols) * vw;
  const Y = vy + ((y + 0.5) / rows) * vh;
  const d = (cx: number, cy: number) => Math.hypot(X - cx, Y - cy);
  const { disc, dot, arc } = SYMBOL;
  if (d(disc.cx, disc.cy) <= disc.r) return "sky";
  if (d(dot.cx, dot.cy) <= dot.r) return "apricot";
  const ra = d(arc.cx, arc.cy);
  if (Y <= arc.cy && Math.abs(ra - arc.r) <= arc.width / 2) return "apricot";
  return undefined;
}

/** Grille du symbole : cols × rows pixels (rows pair : deux pixels par ligne de terminal en demi-blocs). */
export function symbolGrid(cols = 24, rows = 16): (Ink | undefined)[][] {
  return Array.from({ length: rows }, (_, y) => Array.from({ length: cols }, (_, x) => inkAt(x, y, cols, rows)));
}
