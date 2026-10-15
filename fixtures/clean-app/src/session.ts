// Fixture dotation : cookie de session protégé.
import { cookies } from "next/headers";

export async function login(token: string) {
  (await cookies()).set("session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });
}
