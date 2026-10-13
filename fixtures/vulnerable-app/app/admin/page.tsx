"use client";
// Fixture dotation : composant client qui utilise la clé d'administration. Ne pas corriger.
import { createClient } from "@supabase/supabase-js";

const adminKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL ?? "", adminKey);

export default function AdminPage({ bio }: { bio: string }) {
  void supabase;
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
