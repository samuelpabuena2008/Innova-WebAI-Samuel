"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { isAuthApiError, isAuthRetryableFetchError, type Session } from "@supabase/supabase-js";
import { AUTH_CONFIGURED, getSupabase, signOutLocal } from "@/lib/supabase";

/*
 * Estado de la sesión para toda la app (un "contexto" de React: un valor al que acceden los componentes
 * sin pasarlo de padre a hijo; en Java sería como un bean de ámbito de sesión).
 *
 *  - loading     : se está comprobando si ya hay una sesión guardada.
 *  - signed_out  : no hay sesión → se muestra el login.
 *  - signed_in   : hay sesión → se muestra el chat.
 *  - disabled    : el login NO está configurado (modo demo, sin NEXT_PUBLIC_SUPABASE_*) → se muestra el chat.
 *
 * Recordatorio: esto es solo UX. El backend es quien valida el JWT en cada petición.
 */

export type AuthStatus = "loading" | "signed_out" | "signed_in" | "disabled";
export type AppRole = "usuario" | "admin";

export interface AuthUser {
  id: string;
  email: string | null;
  role: AppRole;
}

interface AuthContextValue {
  status: AuthStatus;
  user: AuthUser | null;
  /** Devuelve null si entró bien, o el mensaje de error para mostrar al usuario. */
  signIn: (email: string, password: string) => Promise<string | null>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// El rol se lee igual que en el backend: SOLO de app_metadata.role === "admin" (esa parte solo se edita con la
// clave de servicio). user_metadata lo puede editar el propio usuario, así que nunca se mira.
function toAuthUser(session: Session): AuthUser {
  const role = session.user.app_metadata?.role === "admin" ? "admin" : "usuario";
  return { id: session.user.id, email: session.user.email ?? null, role };
}

// Mensajes en español, sin revelar si el correo existe (un error de credenciales sirve para ambos casos).
function messageFor(error: unknown): string {
  if (isAuthRetryableFetchError(error)) {
    return "No se pudo conectar con el servicio de cuentas. Revisa tu conexión e inténtalo de nuevo.";
  }
  if (isAuthApiError(error)) {
    if (error.status === 429) return "Demasiados intentos. Espera un momento e inténtalo de nuevo.";
    if (error.status >= 500) return "El servicio de cuentas tuvo un problema. Inténtalo de nuevo en unos instantes.";
    if (error.status === 400 || error.status === 401 || error.status === 422) {
      return "Correo o contraseña incorrectos.";
    }
  }
  return "No se pudo iniciar sesión. Inténtalo de nuevo.";
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>(AUTH_CONFIGURED ? "loading" : "disabled");
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    const supabase = getSupabase();
    if (!supabase) return; // modo demo: status ya es "disabled"

    // Supabase avisa en cada cambio: al arrancar (INITIAL_SESSION), al iniciar/cerrar sesión, al renovar el
    // token y cuando otra pestaña cierra la sesión. Una sola función cubre todos los casos.
    // (Dentro del callback no se llama a otras funciones de supabase.auth: puede bloquearse.)
    const { data } = supabase.auth.onAuthStateChange((_evento, session) => {
      setUser(session ? toAuthUser(session) : null);
      setStatus(session ? "signed_in" : "signed_out");
    });
    return () => data.subscription.unsubscribe();
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const supabase = getSupabase();
    if (!supabase) return "El inicio de sesión no está configurado en este despliegue.";
    try {
      const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
      return error ? messageFor(error) : null; // si salió bien, onAuthStateChange cambia el estado
    } catch (error) {
      return messageFor(error);
    }
  }, []);

  const signOut = useCallback(async () => {
    await signOutLocal(); // onAuthStateChange pasa a signed_out y se muestra el login
  }, []);

  const value = useMemo(() => ({ status, user, signIn, signOut }), [status, user, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth debe usarse dentro de <AuthProvider>");
  return ctx;
}
