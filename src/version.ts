import { readFileSync } from "node:fs";
import { packagePath } from "./paths.js";

export const VERSION: string = (JSON.parse(readFileSync(packagePath("package.json"), "utf8")) as { version: string })
  .version;
