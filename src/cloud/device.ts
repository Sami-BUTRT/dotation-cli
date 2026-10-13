// Connexion du CLI par le flux appareil (RFC 8628) : un code s'affiche, la personne l'approuve dans son navigateur.
import { CloudError, request } from "./client.js";

export const CLIENT_ID = "dotation-cli";

export interface DeviceStart {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

export interface DeviceToken {
  access_token: string;
  token_type: string;
  scope: string;
  expires_in?: number;
}

export interface DeviceDeps {
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

const realDeps: DeviceDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now() };

export async function startDevice(base: string, scopes: readonly string[]): Promise<DeviceStart> {
  return request<DeviceStart>(base, "/v1/auth/device/code", {
    method: "POST",
    form: { client_id: CLIENT_ID, scope: scopes.join(" ") },
  });
}

/**
 * Interroge le point de jeton jusqu'à l'approbation, au rythme demandé par le serveur (+5 s à chaque slow_down),
 * sans dépasser l'expiration du code. Lève CloudError (access_denied, expired_token…) sinon.
 */
export async function pollDevice(base: string, start: DeviceStart, deps: DeviceDeps = realDeps): Promise<DeviceToken> {
  let interval = Math.max(1, start.interval) * 1000;
  const deadline = deps.now() + start.expires_in * 1000;
  for (;;) {
    await deps.sleep(interval);
    if (deps.now() > deadline) throw new CloudError(400, "expired_token", "code expired");
    try {
      return await request<DeviceToken>(base, "/v1/auth/device/token", {
        method: "POST",
        form: {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: start.device_code,
          client_id: CLIENT_ID,
        },
      });
    } catch (e) {
      if (!(e instanceof CloudError)) throw e;
      if (e.code === "authorization_pending") continue;
      if (e.code === "slow_down") {
        interval += 5000;
        continue;
      }
      if (e.code === "network") continue; // coupure passagère : on réessaie jusqu'à l'expiration
      throw e;
    }
  }
}
