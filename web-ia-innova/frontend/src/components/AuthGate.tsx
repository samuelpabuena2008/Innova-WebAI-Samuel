"use client";

import type { ReactNode } from "react";
import { useAuth } from "@/hooks/useAuth";
import LoginScreen from "./LoginScreen";

/*
 * Portero de la app: decide qué se ve según la sesión.
 *   loading    -> aviso de carga (evita el parpadeo de mostrar el login a quien ya tiene sesión)
 *   signed_out -> pantalla de login
 *   signed_in / disabled -> el contenido (el chat)
 * Es solo UX: aunque alguien saltara este portero, el backend rechaza cada petición sin un JWT válido.
 */
export default function AuthGate({ children }: { children: ReactNode }) {
  const { status } = useAuth();

  if (status === "loading") {
    return (
      <div className="auth-loading" role="status">
        Comprobando tu sesión…
      </div>
    );
  }
  if (status === "signed_out") return <LoginScreen />;
  return <>{children}</>;
}
