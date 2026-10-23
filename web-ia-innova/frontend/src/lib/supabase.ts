import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/*
 * Cliente de Supabase Auth (MVP-1). Solo se usa para iniciar y cerrar sesión y para obtener el access
 * token (JWT) que orchestratorApi.ts manda al backend en `Authorization: Bearer ...`.
 *
 * IMPORTANTE (seguridad): el login del frontend es solo comodidad de UX. Quien protege los datos es el
 * BACKEND, que valida el JWT en cada petición. Por eso aquí no hay lógica de permisos "de verdad".
 *
 * Todo lo que empieza por NEXT_PUBLIC_ viaja al navegador. La clave que va aquí es la PÚBLICA de Supabase
 * (publishable / anon): está pensada para estar en el navegador y no da más acceso que el que permitan las
 * políticas de la base de datos. La clave de servicio (service_role / sb_secret_...) es la llave maestra:
 * jamás aquí. Más abajo hay una guarda que se niega a usarla si alguien la pega por error.
 */

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
// Se aceptan los dos nombres: "publishable key" (el actual de Supabase) y "anon key" (el histórico).
const PUBLIC_KEY = (
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
)?.trim();

/** True si la clave es una llave secreta/de servicio (nunca debe estar en el navegador). */
export function isSecretKey(key: string): boolean {
  if (key.startsWith("sb_secret_")) return true;
  // Claves antiguas: un JWT cuyo payload dice role = service_role.
  const payload = key.split(".")[1];
  if (!payload) return false;
  try {
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return (JSON.parse(json) as { role?: unknown }).role === "service_role";
  } catch {
    return false; // no es un JWT legible: se trata como clave normal
  }
}

/**
 * Configuración válida del login, o null si falta o es incorrecta. Se calcula UNA vez al cargar el módulo,
 * así los avisos de error salen una sola vez y `AUTH_CONFIGURED` y `getSupabase()` no pueden discrepar.
 *
 * Una configuración incorrecta se trata como "sin configurar" (modo demo) en vez de dejar que supabase-js
 * lance una excepción dentro de un efecto de React, que tumbaría toda la página en blanco. En ese caso el
 * backend, que sí exige sesión, responderá 401 y el chat explicará que falta configurar el login.
 */
function resolveConfig(): { url: string; key: string } | null {
  if (!SUPABASE_URL || !PUBLIC_KEY) return null;
  try {
    const { protocol } = new URL(SUPABASE_URL);
    if (protocol !== "https:" && protocol !== "http:") throw new Error("protocolo no permitido");
  } catch {
    console.error("NEXT_PUBLIC_SUPABASE_URL no es una URL válida (se espera https://<proyecto>.supabase.co).");
    return null;
  }
  if (isSecretKey(PUBLIC_KEY)) {
    // Mensaje fijo (sin imprimir la clave). Se trata como "sin configurar": la app no arranca con ella.
    console.error(
      "NEXT_PUBLIC_SUPABASE_* contiene una clave SECRETA (service_role / sb_secret_). " +
        "Es la llave maestra: quítala de las variables públicas, rótala en Supabase y usa la clave pública.",
    );
    return null;
  }
  return { url: SUPABASE_URL, key: PUBLIC_KEY };
}

const CONFIG = resolveConfig();

// true si el login está configurado. La UI lo usa para decidir si exige iniciar sesión.
// Analogía Java: un flag de configuración leído una sola vez al arrancar, como un @Value.
export const AUTH_CONFIGURED = CONFIG !== null;

let client: SupabaseClient | null | undefined;

/**
 * Cliente único (singleton) o null si no hay login configurado o se ejecuta en el servidor.
 * Se crea de forma perezosa y solo en el navegador: durante el build de Next no hay sesión ni localStorage.
 */
export function getSupabase(): SupabaseClient | null {
  if (typeof window === "undefined") return null;
  if (client !== undefined) return client;
  try {
    client = CONFIG
      ? createClient(CONFIG.url, CONFIG.key, {
          auth: {
            persistSession: true, // la sesión sobrevive a recargar la página (localStorage)
            autoRefreshToken: true, // renueva el JWT antes de que caduque
            detectSessionInUrl: false, // no usamos enlaces mágicos ni OAuth: nada que leer de la URL
          },
        })
      : null;
  } catch {
    // Red de seguridad por si supabase-js rechaza algo que la validación de arriba dejó pasar.
    console.error("No se pudo crear el cliente de Supabase: revisa NEXT_PUBLIC_SUPABASE_*.");
    client = null;
  }
  return client;
}

/** Access token (JWT) vigente, o null si no hay sesión o no se pudo renovar. Nunca lanza. */
export async function getAccessToken(): Promise<string | null> {
  try {
    const supabase = getSupabase();
    if (!supabase) return null;
    // getSession() devuelve la sesión guardada y la renueva si el token ya caducó.
    const { data } = await supabase.auth.getSession();
    return data.session?.access_token ?? null;
  } catch {
    return null;
  }
}

/**
 * Cierra la sesión SOLO en este navegador. El valor por defecto de Supabase ("global") cerraría también la
 * sesión del usuario en todos sus demás dispositivos, que sorprende y no es lo que se espera de "Cerrar sesión".
 */
export async function signOutLocal(): Promise<void> {
  try {
    await getSupabase()?.auth.signOut({ scope: "local" });
  } catch {
    /* si falla (sin red), la sesión local igualmente se descarta en el siguiente arranque o al caducar */
  }
}
