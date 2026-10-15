import { execFile } from "node:child_process";

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface RunOptions {
  cwd?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  maxBuffer?: number;
}

/**
 * Lance un programme SANS shell (aucune interprétation des arguments), avec délai maximal.
 * Ne rejette jamais : un échec de lancement donne code -1 et le message dans stderr.
 */
export function run(cmd: string, args: readonly string[], opts: RunOptions = {}): Promise<RunResult> {
  return new Promise((resolve) => {
    try {
      execFile(
        cmd,
        [...args],
        {
          cwd: opts.cwd,
          timeout: opts.timeoutMs ?? 60_000,
          killSignal: "SIGKILL",
          maxBuffer: opts.maxBuffer ?? 64 * 1024 * 1024,
          env: opts.env ?? process.env,
          windowsHide: true,
          encoding: "utf8",
        },
        (err, stdout, stderr) => {
          if (!err) return resolve({ code: 0, stdout, stderr, timedOut: false });
          const e = err as NodeJS.ErrnoException & { code?: number | string; killed?: boolean; signal?: string };
          const timedOut = e.killed === true && e.signal === "SIGKILL";
          const code = typeof e.code === "number" ? e.code : -1;
          resolve({ code, stdout: stdout ?? "", stderr: stderr || e.message, timedOut });
        },
      );
    } catch (e) {
      // execFile peut lever tout de suite (ex. ENOTDIR : une entrée du PATH est un fichier).
      resolve({ code: -1, stdout: "", stderr: e instanceof Error ? e.message : String(e), timedOut: false });
    }
  });
}

/** Le programme existe-t-il dans le PATH ? */
export async function hasCommand(
  cmd: string,
  versionArgs: readonly string[] = ["--version"],
  env?: NodeJS.ProcessEnv,
): Promise<boolean> {
  const r = await run(cmd, versionArgs, { timeoutMs: 15_000, ...(env ? { env } : {}) });
  return r.code === 0;
}
