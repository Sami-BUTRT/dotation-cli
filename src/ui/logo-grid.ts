// copie de web/src/lib/logo-grid.ts : garder synchronisé (un test vérifie que les deux fichiers sont identiques)
// Grille du logo (40 colonnes × 21 lignes utiles) reprise de la maquette.
// Chaque ligne liste des colonnes ou des plages "a-b".
export const RED: Readonly<Record<number, string>> = {
  0: "4-9",
  1: "3-10",
  2: "2-11",
  3: "1-12",
  4: "0-13",
  5: "0-13",
  6: "0-7,9-13",
  7: "0-11,13",
  8: "0-2,5-13",
  9: "0-2,5-9,11-12",
  10: "3-5,10-11",
  11: "2-4,6-10",
  12: "1,5,8",
  13: "0,3-4",
  15: "7,9",
  16: "3",
  17: "1,6-7",
  19: "5",
  20: "5",
};

export const INK: Readonly<Record<number, string>> = {
  0: "23-24,34-39",
  1: "23-24,34-39",
  2: "23-24,34-39",
  3: "22-25,34-39",
  4: "21-26,34-39",
  5: "21-26,34-39",
  6: "20-27,34-39",
  7: "20-24,26-27,34-39",
  8: "21-23,25-28,34-35,38-39",
  9: "21-23,26-28,35,37-38",
  10: "19-21,24,26-27,35,38-39",
  11: "19-21,24,26,29-30,34,36-37",
  12: "19-25,30,34,36",
  13: "17,20,27,35,38",
  14: "23,35,37",
  15: "19-20,23,26,34-35",
  16: "19,23-24,30",
  18: "26,30,34",
};

/** Dimensions du canevas de la pluie de pixels (la pluie tombe sous le logo). */
export const LOGO_COLS = 40;
export const LOGO_ROWS = 30;

export type Cell = { x: number; y: number; c: "r" | "k" };

export function expand(spec: string): number[] {
  return spec.split(",").flatMap((part) => {
    const [a, b] = part.split("-").map(Number) as [number, number | undefined];
    return b === undefined || Number.isNaN(b) ? [a] : Array.from({ length: b - a + 1 }, (_, i) => a + i);
  });
}

/** Cellules d'une grille, dans l'ordre d'insertion des clés (même ordre que la maquette). */
export function cells(spec: Readonly<Record<number, string>>, c: Cell["c"]): Cell[] {
  return Object.keys(spec).flatMap((row) => expand(spec[Number(row)] ?? "").map((x) => ({ x, y: Number(row), c })));
}

/** Toutes les cellules du logo : rouge puis encre. */
export const LOGO_CELLS: readonly Cell[] = [...cells(RED, "r"), ...cells(INK, "k")];
