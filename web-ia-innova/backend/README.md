# IA Gestora / Orquestadora — Backend básico (avance)

API en FastAPI que recibe un mensaje, decide a qué modelo iría y devuelve una respuesta normalizada. La decisión es **híbrida**: reglas explícitas por prioridad (matriz de delegación del informe) y, solo en los casos ambiguos, una clasificación real con **Google Gemini Flash-Lite**.

## Qué es real y qué sigue simulado

| Parte | Estado |
|-------|--------|
| **Clasificación** (IA Gestora) | **Real** con Gemini Flash-Lite si hay clave y `GESTORA_MODE=hybrid`. Sin clave funciona igual con reglas. |
| **Generación de la respuesta** | **Simulada** (`PROVIDER_MODE=mock`). Las llamadas a OpenAI / Anthropic / NVIDIA **no están implementadas** (`RealProvider`). |
| **Autenticación** | **Real** (MVP-1): `/orchestrate` y `/me` exigen un JWT de Supabase. Ver [`../docs/AUTH-SUPABASE.md`](../docs/AUTH-SUPABASE.md). |
| Límites por cliente, persistencia | No existen todavía. |

Los nombres de modelo vienen del informe y deben validarse.

## Cómo decide la Gestora (modo híbrido)

1. La regla 10 (`procesamiento_privado`) se evalúa **siempre primero** y de forma determinista. Si coincide, **el texto nunca se envía a Gemini**. Detecta palabras clave (sin tildes, por palabra completa, con homoglifos y texto pegado de PDF/Word) y datos personales por patrón (correo, secuencias largas de dígitos).
2. Si coincide una regla de señal fuerte (20, 30, 40 o 50) decide la regla, sin llamar a Gemini.
3. Si solo coincidiría la regla 60 (`tarea_breve`) o la regla por defecto, **clasifica Gemini**.
4. Si Gemini falla (sin clave, timeout, 429, JSON inválido, categoría desconocida o tope local de llamadas), se usan las reglas. La app nunca se cae por la Gestora.

La respuesta incluye `decided_by`: `regla`, `gestora_llm` o `regla_respaldo`.

### Aviso de privacidad
En el **nivel gratis** de Gemini, Google puede usar el contenido para mejorar sus productos. Por eso:
- solo se envían los **primeros 2000 caracteres**;
- los mensajes detectados como confidenciales **nunca** llegan a Gemini;
- no se registra en logs ni el mensaje ni la respuesta cruda de Gemini (solo categoría, modelo, latencia y códigos de error).

La detección es por reglas: **no es perfecta**. No envíes datos sensibles.

## Contrato (el que usa el frontend)

`POST /orchestrate` (requiere `Authorization: Bearer <JWT de Supabase>`)

```json
{ "message": "texto del usuario" }
```

El mensaje se recorta de espacios y admite hasta **32 000 caracteres** (422 si está vacío o se pasa).

Respuesta 200:

```json
{
  "request_id": "uuid",
  "content": "...",
  "model": "gpt-5.6-terra",
  "category": "automatizacion_cotidiana",
  "reason": "Tarea normal y variada",
  "latency_ms": 12,
  "fallback_used": false,
  "is_mock": true,
  "decided_by": "regla"
}
```

Errores: **401** `{ "detail": "No autenticado" }` sin token o con un token inválido, vencido o de otro proyecto (el motivo exacto solo va a los logs) · **503** `{ "detail": "Autenticación no disponible." }` si la autenticación no está configurada o Supabase no responde · **422** entrada inválida · **502** `{ "detail": "..." }` si ningún proveedor responde · **503** si un mensaje privado llega con `PROVIDER_MODE=real` y no hay `PRIVATE_ROUTE_URL` (https) configurada. Lo privado **no tiene modelo de respaldo**: nunca se reenvía a otro proveedor.

`GET /me` (requiere token) → `{ "id", "email", "role" }`, con `role` = `usuario` o `admin` sacado de `app_metadata.role` del token verificado.

`GET /health` → `{ "status", "provider_mode", "gestora_mode", "api_key_configured" }`. Nunca devuelve la clave.

## Variables de entorno

Copia `.env.example` a `.env` (Git lo ignora). **Nunca subas el `.env`.**

| Variable | Para qué | Por defecto |
|----------|----------|-------------|
| `PROVIDER_MODE` | `mock` (simulado) o `real` | `mock` |
| `ALLOWED_ORIGINS` | Orígenes CORS, separados por comas | `http://localhost:3000` |
| `GESTORA_MODE` | `hybrid` (reglas + Gemini) o `rules` | `hybrid` si hay clave, si no `rules` |
| `GEMINI_API_KEY` | Clave de Google AI Studio | vacío |
| `GEMINI_MODEL` | ID del modelo | `gemini-3.5-flash-lite` |
| `GESTORA_TIMEOUT_S` | Espera máxima a Gemini | `4` |
| `GESTORA_MAX_CALLS_PER_MIN` | Tope local de llamadas a Gemini | `15` |
| `PRIVATE_ROUTE_URL` | Ruta privada (https) para el modo real | vacío |
| `AUTH_MODE` | `required` o `disabled` (solo con `PROVIDER_MODE=mock`; con `real` se rechaza con 503). Cualquier otro valor deja la autenticación **activada** | `required` |
| `SUPABASE_URL` | URL del proyecto de Supabase; de ahí salen el emisor del token y el JWKS. Sin ella: 503 | vacío |
| `SUPABASE_JWT_SECRET` | Opcional: secreto HS256 "legado" de Supabase | vacío |

### Cómo obtener la clave de Gemini
1. Entra a [Google AI Studio](https://aistudio.google.com/apikey) con tu cuenta de Google.
2. Crea una clave de API.
3. Pégala tú mismo en `backend/.env` como `GEMINI_API_KEY=...` (no la pongas en el chat, en el frontend ni en variables `NEXT_PUBLIC_*`).
4. Los límites del nivel gratis (RPM/RPD) se consultan en AI Studio; la documentación pública no publica las cifras.

## Ejecutar en local

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env      # y rellena GEMINI_API_KEY si quieres la Gestora real
uvicorn app.main:app --reload --port 8000 --env-file .env
```

Para desarrollar **sin Supabase**, pon `AUTH_MODE=disabled` en tu `.env` (solo vale con `PROVIDER_MODE=mock`); si no, `/orchestrate` responderá 401/503.

El código **no lee** el `.env`: lo carga uvicorn con `--env-file .env` (por eso hay que pasarlo al arrancar). Sin esa opción la clave no se carga y la Gestora funciona solo con reglas.

Documentación interactiva: http://localhost:8000/docs

## Probar

```powershell
python -m unittest -v
```

Las pruebas **no usan la red ni la clave real** (`tests/__init__.py` descarta cualquier `GEMINI_API_KEY` del entorno y las pruebas usan un clasificador falso).

## Desplegar

Hugging Face Spaces con SDK **Docker** (el Dockerfile escucha en `${PORT:-7860}` y corre sin root) **exige un plan de pago para crear el Space** (verificado en la documentación de Hugging Face). La decisión de hosting sigue abierta; el Dockerfile es portable a otros servicios.

1. Sube Dockerfile, requirements.txt y la carpeta app/.
2. Variables y Secrets del hosting: `ALLOWED_ORIGINS`, `GEMINI_API_KEY`, etc. El contenedor no incluye ningún `.env` (lo excluye `.dockerignore`) y el código tampoco lo lee.
3. La URL pública es la que va en `NEXT_PUBLIC_ORCHESTRATOR_URL` del frontend.

El Dockerfile aún no se ha probado con `docker build` en este equipo.

## Pendientes

- **Bloquean `PROVIDER_MODE=real`:** límite de uso por usuario/cliente (rate limit y cuotas; la autenticación con JWT de Supabase ya está hecha); decidir dónde corre la ruta privada y crear un proveedor privado que use `PRIVATE_ROUTE_URL`; evaluar la Gestora (G-01).
- Panel de administración (MVP-8): `require_admin` ya existe, falta una ruta que lo use.
- Implementar `RealProvider` por proveedor (adaptadores independientes).
- Guardar métricas en Supabase y mover las reglas a configuración editable.
- Detalle y estado de cada hallazgo: [`../REVIEW-2026-10.md`](../REVIEW-2026-10.md).
