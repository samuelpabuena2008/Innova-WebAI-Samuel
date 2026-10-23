# Web IA INNOVA — Frontend

Interfaz de chat (Next.js App Router + React + TypeScript, CSS propio) para la plataforma multimodelo del grupo INNOVA.

## Cómo ejecutarlo (Windows, terminal de VS Code)

```powershell
npm install
npm run dev
```

Abre http://localhost:3000. Requiere Node.js 18.18+ (recomendado 20 LTS).

## Estado actual

- Chat funcional: enviar con botón o Enter (Shift+Enter = salto de línea), nueva conversación, historial en memoria, indicador de carga, errores y aviso sin conexión, diseño responsive.
- **Las respuestas son DATOS DE PRUEBA** mientras `NEXT_PUBLIC_ORCHESTRATOR_URL` esté vacía. Se marcan con la etiqueta "Datos de prueba".
- El historial se pierde al recargar (persistencia con Supabase: fase futura).
- **Login cerrado con Supabase (MVP-1):** sin sesión se ve la pantalla de acceso; con sesión, el chat, con el correo, el rol y "Cerrar sesión" en la barra lateral. Si `NEXT_PUBLIC_SUPABASE_URL` está vacía, no se pide login (modo demo). Guía de configuración: [`../docs/AUTH-SUPABASE.md`](../docs/AUTH-SUPABASE.md).
- Adjuntar archivos y configuración: botones desactivados (próximamente).

## Estructura

```text
src/
├── app/            layout.tsx, page.tsx, globals.css
├── components/     ChatApp, Sidebar, ChatMessage, ChatInput, ModelInfo, LoadingIndicator, WelcomeScreen,
│                   AuthGate (decide login o chat), LoginScreen
├── hooks/          useChat.ts   (toda la lógica del chat), useAuth.tsx   (estado de la sesión)
├── lib/            supabase.ts   (único archivo que crea el cliente de Supabase)
├── services/       orchestratorApi.ts   (único archivo que habla con el backend; envía el JWT)
└── types/          chat.ts
```

## Conectar el orquestador

1. Copia `.env.example` a `.env.local` y pon la URL base del orquestador.
2. Confirma con backend: endpoint, método, campos de entrada y de respuesta.
3. Ajusta SOLO `src/services/orchestratorApi.ts` (`ENDPOINT_PATH`, cuerpo de la petición y `parseResponse`).

El contrato está **confirmado con el backend**: `POST {URL}/orchestrate` con `{ "message": "..." }` y la cabecera `Authorization: Bearer <JWT de Supabase>`; respuesta con `content` y, opcionalmente, `model`, `category`, `reason`, `latency_ms`, `is_mock`, `decided_by`. La interfaz muestra únicamente los metadatos que lleguen. Un 401 cierra la sesión local y vuelve al login con un aviso.

## Seguridad

Nunca pongas claves de OpenAI, Anthropic o NVIDIA en este proyecto. Variables con prefijo `NEXT_PUBLIC_` son visibles en el navegador: solo URLs y la clave **pública** de Supabase (publishable / anon). La clave secreta o `service_role` de Supabase es la llave maestra: si se detecta en `NEXT_PUBLIC_*`, la app se niega a usarla (pero habría que rotarla). El login del frontend es solo comodidad: quien protege los datos es el backend, que valida el JWT en cada petición.

## Despliegue en Vercel

Sube el repositorio a GitHub, impórtalo en Vercel y define `NEXT_PUBLIC_ORCHESTRATOR_URL`, `NEXT_PUBLIC_SUPABASE_URL` y `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` en Settings → Environment Variables (se incrustan al compilar: si las cambias, vuelve a desplegar). Es un monorepo: Root Directory = `web-ia-innova/frontend`.
