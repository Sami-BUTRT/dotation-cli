"use client";
// Fixture dotation : composant client qui n'utilise que la clé anon.
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL ?? "", process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "");

export default function Profile({ bio }: { bio: string }) {
  void supabase;
  return <p>{bio}</p>;
}
