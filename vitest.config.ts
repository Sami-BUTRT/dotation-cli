import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    testTimeout: 120_000,
    // Les tests des moteurs externes lancent de vrais sous-processus : un seul fichier à la fois limite la charge sur le VPS.
    fileParallelism: false,
  },
});
