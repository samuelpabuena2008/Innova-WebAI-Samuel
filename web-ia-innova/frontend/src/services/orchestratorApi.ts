import { AUTH_CONFIGURED, getAccessToken, signOutLocal } from "@/lib/supabase";
import type { OrchestratorRequest, OrchestratorResult, ResponseMeta } from "@/types/chat";

/*
 * Capa de servicios: es el ÚNICO archivo que habla con el orquestador.
 * Si el contrato de la API cambia, solo se modifica este archivo.
 *
 * CONTRATO CONFIRMADO por el backend (backend/app/schemas.py):
 *  - POST {API_URL}/orchestrate con cuerpo { message }.
 *  - MVP-1: la cabecera `Authorization: Bearer <JWT de Supabase>` es OBLIGATORIA; sin ella (o con un token
 *    vencido) el backend responde 401. Ver más abajo cómo se trata.
 *  - `conversationId` NO se envía por ahora (el backend aún no lo usa).
 *  - La respuesta trae content y metadatos opcionales (model, category, reason,
 *    latency_ms, is_mock, decided_by).
 *  Aun así parseResponse() sigue siendo tolerante: solo lee campos que existan y
 *  tengan el tipo esperado, así un campo nuevo o ausente no rompe la UI.
 */

const API_URL = process.env.NEXT_PUBLIC_ORCHESTRATOR_URL;
const TIMEOUT_MS = 30_000;
const ENDPOINT_PATH = "/orchestrate"; // confirmado por el backend

// true si hay backend configurado. La UI lo usa para mostrar el aviso de la IA Gestora
// (sin backend no hay Gemini y el aviso sería falso).
export const ORCHESTRATOR_CONFIGURED = Boolean(API_URL);

// B-09: longitud máxima del mensaje. DEBE coincidir con MAX_MESSAGE_CHARS del backend
// (backend/app/schemas.py). Analogía Java: una constante compartida del contrato, como
// un `public static final int` que cliente y servidor deben mantener sincronizada a mano.
export const MAX_MESSAGE_CHARS = 32_000;

export class OrchestratorError extends Error {}

// 401: el backend no reconoció la sesión. Es una subclase para que useChat siga mostrando el mensaje igual
// (captura OrchestratorError), pero se puede distinguir si hiciera falta.
export class AuthRequiredError extends OrchestratorError {}

export async function sendMessage(req: OrchestratorRequest): Promise<OrchestratorResult> {
  // Sin URL configurada -> datos de prueba, claramente marcados.
  if (!API_URL) return mockResponse(req);

  // MVP-1: JWT de la sesión (Supabase lo renueva solo si ya caducó). null = no hay sesión o login sin configurar.
  // Se pide ANTES de armar el temporizador para que renovar el token no cuente contra el tiempo de espera.
  const token = await getAccessToken();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${API_URL}${ENDPOINT_PATH}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ message: req.message }), // campos confirmados; sin conversationId
      signal: controller.signal,
    });

    // MVP-1: 401 = el backend no aceptó la sesión (token vencido, usuario dado de baja o sin login).
    // Se cierra la sesión local: AuthGate vuelve a mostrar el login para entrar de nuevo.
    if (res.status === 401) {
      if (AUTH_CONFIGURED) {
        await signOutLocal();
        throw new AuthRequiredError("Tu sesión expiró o ya no es válida. Inicia sesión de nuevo.");
      }
      // Login sin configurar en este despliegue pero el backend lo exige: es un error de configuración.
      throw new AuthRequiredError(
        "El servidor exige iniciar sesión, pero este despliegue no tiene configurado el login " +
          "(faltan NEXT_PUBLIC_SUPABASE_URL y la clave pública).",
      );
    }
    if (res.status === 403) {
      throw new OrchestratorError("No tienes permiso para hacer esto.");
    }
    // F-05: mensaje distinto según el estado HTTP.
    if (res.status === 429) {
      throw new OrchestratorError("Demasiadas solicitudes, espera un momento e inténtalo de nuevo.");
    }
    if (res.status >= 500) {
      throw new OrchestratorError("El servidor tuvo un problema. Inténtalo de nuevo en unos instantes.");
    }
    if (!res.ok) {
      throw new OrchestratorError(`El servidor respondió con error ${res.status}. Intenta de nuevo.`);
    }

    // F-05: un JSON inválido NO es un fallo de red; se separa para no decir "revisa tu conexión".
    // Analogía Java: capturar JsonParseException aparte de IOException.
    let data: unknown;
    try {
      data = await res.json();
    } catch {
      throw new OrchestratorError("La respuesta del servidor tiene un formato inesperado.");
    }
    return parseResponse(data);
  } catch (error) {
    if (error instanceof OrchestratorError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new OrchestratorError("La solicitud tardó demasiado. Intenta de nuevo.");
    }
    throw new OrchestratorError("No se pudo conectar con el servidor. Revisa tu conexión.");
  } finally {
    clearTimeout(timer);
  }
}

function parseResponse(data: unknown): OrchestratorResult {
  if (typeof data !== "object" || data === null) {
    throw new OrchestratorError("La respuesta del servidor no tiene el formato esperado.");
  }
  const d = data as Record<string, unknown>;

  const content =
    typeof d.content === "string" ? d.content : typeof d.response === "string" ? d.response : null;
  if (content === null) {
    throw new OrchestratorError("La respuesta del servidor no incluye contenido.");
  }

  // Solo copiamos lo que realmente llegó. Nada se inventa.
  const meta: ResponseMeta = {};
  if (typeof d.model === "string") meta.model = d.model;
  if (typeof d.category === "string") meta.category = d.category;
  if (typeof d.reason === "string") meta.reason = d.reason;
  if (typeof d.latency_ms === "number") meta.latencyMs = d.latency_ms;
  if (d.is_mock === true) meta.isMock = true; // el backend avisa que la respuesta es simulada

  // Lectura tolerante: solo los tres valores conocidos; cualquier otro (o ausencia) se ignora.
  if (d.decided_by === "regla" || d.decided_by === "gestora_llm" || d.decided_by === "regla_respaldo") {
    meta.decidedBy = d.decided_by;
  }

  return { content, meta: Object.keys(meta).length > 0 ? meta : undefined };
}

function mockResponse(req: OrchestratorRequest): Promise<OrchestratorResult> {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        content:
          `Esta es una respuesta de prueba. Recibí tu mensaje: «${req.message}». ` +
          "Cuando el orquestador esté conectado, aquí aparecerá la respuesta real.",
        meta: { isMock: true },
      });
    }, 1200);
  });
}
