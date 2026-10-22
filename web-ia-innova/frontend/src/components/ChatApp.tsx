"use client";

import { useEffect, useRef, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useChat } from "@/hooks/useChat";
import ChatInput from "./ChatInput";
import ChatMessage from "./ChatMessage";
import LoadingIndicator from "./LoadingIndicator";
import Sidebar from "./Sidebar";
import WelcomeScreen from "./WelcomeScreen";

export default function ChatApp() {
  const { conversations, activeConversation, isLoading, isOnline, send, newConversation, selectConversation } =
    useChat();
  const { status, user, signOut } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const menuBtnRef = useRef<HTMLButtonElement>(null);

  // Baja automáticamente al último mensaje.
  // F-08: si el usuario pidió menos movimiento, el salto es instantáneo (sin scroll suave).
  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    bottomRef.current?.scrollIntoView({ behavior: reduce ? "auto" : "smooth" });
  }, [activeConversation.messages.length, isLoading]);

  // F-01: al cerrar la barra lateral devolvemos el foco al botón de menú (que la abrió).
  // Analogía Java: como el finally que restaura el estado previo al salir de un diálogo modal.
  function closeSidebar() {
    setSidebarOpen(false);
    menuBtnRef.current?.focus();
  }

  // F-01: Escape cierra la barra lateral solo mientras está abierta.
  useEffect(() => {
    if (!sidebarOpen) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") closeSidebar();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [sidebarOpen]);

  const isEmpty = activeConversation.messages.length === 0;

  return (
    <div className="app">
      <Sidebar
        conversations={conversations}
        activeId={activeConversation.id}
        isOpen={sidebarOpen}
        onClose={closeSidebar}
        onNew={newConversation}
        onSelect={selectConversation}
        account={status === "signed_in" && user ? { email: user.email, role: user.role } : undefined}
        onSignOut={signOut}
      />

      <main className="main">
        <header className="topbar">
          <button
            ref={menuBtnRef}
            type="button"
            className="icon-btn menu-btn"
            onClick={() => setSidebarOpen(true)}
            aria-label="Abrir barra lateral"
          >
            ☰
          </button>
          <span className="topbar__title">{activeConversation.title}</span>
        </header>

        {!isOnline && (
          <div className="banner" role="alert">
            Sin conexión a internet. Podrás enviar mensajes cuando vuelva.
          </div>
        )}

        <div className="messages">
          {isEmpty && <WelcomeScreen onPick={send} />}
          {/* F-02: el contenedor role="log" es PERSISTENTE (siempre montado, aunque esté vacío).
              Los lectores de pantalla solo anuncian cambios en regiones que ya existían:
              si lo montáramos junto con el primer mensaje, ese primer mensaje no se leería.
              Analogía Java: como un Logger ya registrado en un appender; los "additions"
              son las nuevas líneas de log que se anuncian, sin releer las anteriores. */}
          <div
            className={`messages__inner${isEmpty ? " messages__inner--empty" : ""}`}
            role="log"
            aria-live="polite"
            aria-relevant="additions"
            aria-label="Conversación"
          >
            {activeConversation.messages.map((m) => (
              <ChatMessage key={m.id} message={m} />
            ))}
            {isLoading && <LoadingIndicator />}
            <div ref={bottomRef} />
          </div>
        </div>

        <ChatInput onSend={send} disabled={isLoading || !isOnline} />
      </main>
    </div>
  );
}
