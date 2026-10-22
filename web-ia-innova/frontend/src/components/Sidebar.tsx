"use client";

import { useSyncExternalStore } from "react";
import type { AppRole } from "@/hooks/useAuth";
import type { Conversation } from "@/types/chat";

// Misma frontera que el @media (max-width: 800px) de globals.css.
const MOBILE_QUERY = "(max-width: 800px)";

// Suscripción al media query sin useEffect+useState (evita un render extra y parpadeos).
// Analogía Java: un PropertyChangeListener que notifica solo cuando cambia el valor.
function subscribeMobile(onChange: () => void) {
  const mql = window.matchMedia(MOBILE_QUERY);
  mql.addEventListener("change", onChange);
  return () => mql.removeEventListener("change", onChange);
}
const getMobileSnapshot = () => window.matchMedia(MOBILE_QUERY).matches;
const getMobileServerSnapshot = () => false; // en servidor no hay ventana: asumimos escritorio

interface SidebarProps {
  conversations: Conversation[];
  activeId: string;
  isOpen: boolean;
  onClose: () => void;
  onNew: () => void;
  onSelect: (id: string) => void;
  // MVP-1: datos de la sesión. Si no hay sesión (modo demo sin login) no se pasan y "Cuenta" sigue desactivado.
  account?: { email: string | null; role: AppRole };
  onSignOut?: () => void;
}

export default function Sidebar({
  conversations,
  activeId,
  isOpen,
  onClose,
  onNew,
  onSelect,
  account,
  onSignOut,
}: SidebarProps) {
  const isMobile = useSyncExternalStore(subscribeMobile, getMobileSnapshot, getMobileServerSnapshot);
  // F-01: en móvil, cerrada = `inert` (ni foco, ni clics, ni lector de pantalla).
  // En escritorio la barra es fija y siempre interactiva.
  const isInert = isMobile && !isOpen;

  return (
    <>
      {isOpen && <div className="backdrop" onClick={onClose} aria-hidden="true" />}
      <aside
        className={`sidebar${isOpen ? " sidebar--open" : ""}`}
        aria-label="Barra lateral"
        inert={isInert}
      >
        <div className="sidebar__top">
          <span className="brand">
            {/* Decorativo: el nombre de la marca ya está en el texto contiguo */}
            <img src="/logo.svg" alt="" aria-hidden="true" width={32} height={32} />
            Web IA INNOVA
          </span>
          <button type="button" className="icon-btn sidebar__close" onClick={onClose} aria-label="Cerrar barra lateral">
            ×
          </button>
        </div>

        <button type="button" className="new-chat" onClick={() => { onNew(); onClose(); }}>
          + Nueva conversación
        </button>

        <nav className="history" aria-label="Historial de conversaciones">
          {conversations.map((c) => (
            <button
              key={c.id}
              type="button"
              className={`history__item${c.id === activeId ? " history__item--active" : ""}`}
              aria-current={c.id === activeId ? "true" : undefined}
              onClick={() => { onSelect(c.id); onClose(); }}
            >
              {c.title}
            </button>
          ))}
        </nav>

        {/* F-10: aviso honesto; useChat guarda el historial solo en memoria */}
        <p className="sidebar__note">El historial no se guarda todavía: se pierde al recargar la página.</p>

        <div className="sidebar__bottom">
          <button type="button" className="sidebar__link" disabled title="Próximamente">
            Configuración
          </button>
          {account ? (
            <div className="sidebar__account">
              <p className="sidebar__email" title={account.email ?? undefined}>
                {account.email ?? "Sesión iniciada"}
              </p>
              {/* El rol es informativo (sale de la sesión); los permisos reales los aplica el backend. */}
              <span className="badge">{account.role === "admin" ? "Administrador" : "Usuario"}</span>
              <button type="button" className="sidebar__link" onClick={onSignOut}>
                Cerrar sesión
              </button>
            </div>
          ) : (
            <button type="button" className="sidebar__link" disabled title="Próximamente">
              Cuenta
            </button>
          )}
        </div>
      </aside>
    </>
  );
}
