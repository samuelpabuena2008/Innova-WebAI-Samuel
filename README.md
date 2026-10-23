# Innova-WebAI

Plataforma web multimodelo con una **IA Gestora / Orquestadora** que decide qué modelo atiende cada mensaje. Proyecto del grupo INNOVA (U. del Norte).

> **Estado: prototipo.** La generación de respuestas es **simulada** (`PROVIDER_MODE=mock`). Lo real es la **clasificación** de la Gestora con Google Gemini Flash-Lite (solo si se configura una clave) y el **login cerrado con Supabase** (el backend valida el JWT; roles `usuario` / `admin`).

## Estructura

| Carpeta | Contenido |
|---------|-----------|
| `web-ia-innova/frontend` | Chat en Next.js 15 + React 19 + TypeScript |
| `web-ia-innova/backend` | API FastAPI con las reglas de ruteo y la Gestora (ver su [README](web-ia-innova/backend/README.md)) |
| `web-ia-innova/docs/AUTH-SUPABASE.md` | Guía del login con Supabase (cuentas, roles usuario/admin, variables) |
| `web-ia-innova/REVIEW-2026-10.md` | Review de código y estado de cada hallazgo |

## Arranque rápido

```powershell
# Backend (puerto 8000)
cd web-ia-innova/backend
pip install -r requirements.txt
copy .env.example .env   # y pon AUTH_MODE=disabled si aún no tienes Supabase (ver «Login» más abajo)
uvicorn app.main:app --reload --port 8000 --env-file .env

# Frontend (puerto 3000), en otra terminal
cd web-ia-innova/frontend
npm install
copy .env.example .env.local   # NEXT_PUBLIC_ORCHESTRATOR_URL=http://localhost:8000 para usar el backend
npm run dev
```

Sin `NEXT_PUBLIC_ORCHESTRATOR_URL` el frontend responde con datos de prueba sin llamar al backend.

### Login (Supabase)

- **Con Supabase:** sigue [`web-ia-innova/docs/AUTH-SUPABASE.md`](web-ia-innova/docs/AUTH-SUPABASE.md). El backend exige `SUPABASE_URL` y el frontend `NEXT_PUBLIC_SUPABASE_URL` + `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`.
- **Sin Supabase (solo desarrollo con respuestas simuladas):** `AUTH_MODE=disabled` en `backend/.env` y deja vacías las variables de Supabase del frontend. Con `PROVIDER_MODE=real` el backend rechaza `AUTH_MODE=disabled`.

## Pruebas

- Backend: `python -m unittest -v` (en `web-ia-innova/backend`; sin red ni clave).
- Frontend: `npm run build` (aún no hay pruebas de frontend).
- CI: `.github/workflows/ci.yml` ejecuta ambas en cada PR.

## Privacidad y secretos

- Las claves van **solo** en `web-ia-innova/backend/.env` (ignorado por Git). Hay un `.env.example` en backend y frontend. Nunca pongas claves en el frontend ni en variables `NEXT_PUBLIC_*`.
- En el **nivel gratis** de Gemini, Google puede usar el contenido para mejorar sus productos. Solo se envían los primeros 2000 caracteres de los mensajes ambiguos, y los detectados como confidenciales no se envían a Gemini. La detección por reglas no es perfecta: **no envíes datos sensibles**.
- No se registra en logs el contenido de los mensajes.
