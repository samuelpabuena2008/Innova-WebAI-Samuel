"use client";

import { useRef, useState, type FormEvent } from "react";
import { useAuth } from "@/hooks/useAuth";

/*
 * Pantalla de acceso (informe, sección 10: "Inicio / acceso"). El acceso es CERRADO (MVP-1: "login cerrado
 * para miembros de prueba"): no hay registro público; las cuentas las crea un administrador en Supabase.
 * Pendiente (otra fase): recuperación de contraseña.
 */
export default function LoginScreen() {
  const { signIn } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (pending) return; // evita el doble envío (doble clic o Enter repetido)
    setPending(true);
    setError(null);
    const message = await signIn(email, password);
    if (message) {
      setError(message);
      setPassword(""); // no se deja la contraseña fallida en el campo
      setPending(false);
      passwordRef.current?.focus();
    }
    // Si salió bien no se hace nada más: AuthProvider cambia a "signed_in" y este componente se desmonta.
  }

  return (
    <main className="login">
      <form className="login__card" onSubmit={handleSubmit} aria-labelledby="login-title">
        <img className="login__logo" src="/logo.svg" alt="" aria-hidden="true" width={56} height={56} />
        <h1 id="login-title">Iniciar sesión</h1>
        <p className="login__intro">
          El acceso es solo para miembros autorizados de INNOVA. Si necesitas una cuenta, pídesela a un administrador.
        </p>

        <div className="field">
          <label htmlFor="login-email">Correo electrónico</label>
          <input
            id="login-email"
            type="email"
            name="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "login-error" : undefined}
          />
        </div>

        <div className="field">
          <label htmlFor="login-password">Contraseña</label>
          <input
            id="login-password"
            ref={passwordRef}
            type="password"
            name="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "login-error" : undefined}
          />
        </div>

        {/* role="alert": el lector de pantalla anuncia el error en cuanto aparece. */}
        {error && (
          <p id="login-error" className="login__error" role="alert">
            {error}
          </p>
        )}

        <button type="submit" className="login__submit" disabled={pending || !email || !password}>
          {pending ? "Entrando…" : "Entrar"}
        </button>
      </form>
    </main>
  );
}
