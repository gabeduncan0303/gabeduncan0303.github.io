import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL;
const anon = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const BUCKET = import.meta.env.VITE_SUPABASE_BUCKET || "private-media";

export const supabase = createClient(url, anon);
