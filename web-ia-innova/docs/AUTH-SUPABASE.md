# Autenticación con Supabase (MVP-1)

Guía para configurar el login cerrado de Web IA INNOVA: cuentas y roles `usuario` / `admin` en Supabase, y validación del JWT en el backend.

## Cómo funciona

```text
Navegador ──(correo + contraseña)──▶ Supabase Auth ──▶ devuelve un access token (JWT)
Navegador ──(Authorization: Bearer <JWT>)──▶ Backend FastAPI ──▶ valida el JWT ──▶ responde
```

- La contraseña **solo** la ve Supabase. El backend nunca la recibe: solo comprueba el token.
- El backend verifica en **cada petición** (`/orchestrate`, `/me`): la firma, que no haya caducado (`exp`), la audiencia (`aud = authenticated`) y el emisor (`iss` = tu proyecto). Con claves asimétricas (ES256 / RS256) descarga las claves públicas del endpoint JWKS de Supabase (`<SUPABASE_URL>/auth/v1/.well-known/jwks.json`) y las cachea 10 minutos.
- El **frontend solo hace de comodidad** (muestra el login o el chat). Aunque alguien saltara esa pantalla, el backend respondería 401.
- El rol sale de `app_metadata.role` del token. Solo vale `"admin"`; cualquier otra cosa es `usuario`. **Nunca** se lee `user_metadata`, porque el propio usuario puede editarlo desde el navegador.

## 1. Crear el proyecto

1. Crea un proyecto en [supabase.com](https://supabase.com) (el plan gratuito sirve).
2. Anota dos datos de *Project Settings → API*: la **Project URL** (`https://<proyecto>.supabase.co`) y la clave **pública** (*publishable key*, `sb_publishable_...`, o la *anon key* histórica).

> La clave **secreta** (`sb_secret_...` / `service_role`) es la llave maestra. **No** va en el frontend ni en Git. El frontend se niega a usarla si la detecta en `NEXT_PUBLIC_*`, pero si ya la pegaste ahí hay que rotarla.

## 2. Cerrar el acceso (login solo para miembros)

En el panel de Supabase, *Authentication*, ajustes generales (nombres tal como aparecen en la [documentación](https://supabase.com/docs/guides/auth/general-configuration); la ruta exacta de menú puede variar):

| Ajuste | Valor | Por qué |
|--------|-------|---------|
| **Allow new users to sign up** | **Desactivado** | Sin esto cualquiera puede crearse una cuenta. Con esto apagado solo entran las cuentas que crees tú. |
| **Allow anonymous sign-ins** | **Desactivado** | Un inicio anónimo genera un token válido sin correo. El backend ya lo rechaza (`is_anonymous`), pero mejor no ofrecerlo. |
| **Confirm Email** (en *Sign In / Providers → Email*) | Como prefieras | Si las cuentas las creas tú ya confirmadas, no hace falta. |

## 3. Crear los usuarios

*Authentication → Users → Add user*: correo y contraseña, marcando la confirmación automática (en la guía de terceros que consulté el interruptor se llama *Auto-confirm user*). Comparte la contraseña por un canal seguro y pide que la cambien.

## 4. Dar el rol `admin`

El rol vive en `app_metadata`, que **solo** se edita con privilegios de servidor (no lo puede tocar el usuario). Dos formas:

**a) API de administración** (documentada: [`auth.admin.updateUserById`](https://supabase.com/docs/reference/javascript/auth-admin-updateuserbyid), solo desde un servidor y con la clave de servicio):

```js
await supabase.auth.admin.updateUserById(userId, { app_metadata: { role: "admin" } });
```

**b) SQL Editor del panel.** Es lo habitual, pero **no pude contrastarlo con la documentación oficial ni ejecutarlo** (no tengo un proyecto de Supabase), pruébalo primero con un usuario de prueba:

```sql
update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role": "admin"}'::jsonb
where email = 'admin@tu-dominio.com';
```

El cambio llega al token **cuando este se renueva**. La vida del access token es configurable en tu proyecto (no pude confirmar en la documentación cuál es el valor por defecto; suele ser de una hora, compruébalo). Cerrar sesión y volver a entrar lo aplica al instante. Para quitar el rol, repite con `'{"role": "usuario"}'`.

## 5. Variables de entorno

**Backend** (`web-ia-innova/backend/.env`, que Git ignora; en producción, los *Secrets* del hosting):

| Variable | Valor |
|----------|-------|
| `AUTH_MODE` | `required` (por defecto). |
| `SUPABASE_URL` | La Project URL. Sin ella el backend responde 503 y no deja pasar a nadie. |
| `SUPABASE_JWT_SECRET` | **Opcional.** Solo si tu proyecto aún firma con el secreto HS256 "legado" o quieres seguir aceptando tokens firmados con él tras rotar claves. |
| `ALLOWED_ORIGINS` | Debe incluir el origen del frontend (CORS). |

**Frontend** (`web-ia-innova/frontend/.env.local`, o *Environment Variables* de Vercel):

| Variable | Valor |
|----------|-------|
| `NEXT_PUBLIC_SUPABASE_URL` | La misma Project URL. |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | La clave **pública**. |
| `NEXT_PUBLIC_ORCHESTRATOR_URL` | URL del backend. |

Las variables `NEXT_PUBLIC_*` se incrustan al **compilar**: si las cambias en Vercel hay que volver a desplegar.

## 6. Comprobar que funciona

```bash
# Sin token: 401
curl -i -X POST $BACKEND/orchestrate -H "Content-Type: application/json" -d '{"message":"hola"}'

# Con el token de una sesión iniciada: 200, y /me muestra el rol
curl $BACKEND/me -H "Authorization: Bearer $TOKEN"
```

Los logs del backend registran `user=<uuid>` y el **motivo** de cada rechazo (`ExpiredSignatureError`, `InvalidSignatureError`...), nunca el token. Al cliente solo se le dice "No autenticado".

## Desarrollo local sin Supabase

- **Frontend sin `NEXT_PUBLIC_SUPABASE_URL`:** no pide login (modo demo), como antes.
- **Backend con `AUTH_MODE=disabled`:** no exige token. **Solo** con `PROVIDER_MODE=mock`: con `PROVIDER_MODE=real` el backend lo rechaza (503). Cualquier otro valor (`off`, `false`...) deja la autenticación **activada**.
- Para probar contra un Supabase local (`supabase start`) basta `SUPABASE_URL=http://127.0.0.1:54321` (http solo se acepta hacia localhost).

## Limitaciones conocidas

- **Un token ya emitido sigue valiendo hasta que caduque.** Si das de baja a un usuario o le quitas el rol admin, conserva el acceso hasta que expire su token (o hasta que se renueve, en el caso del rol). Para una revocación inmediata habría que consultar a Supabase en cada petición o llevar una lista de bloqueo.
- **Sin límite de peticiones por usuario** (resto de S-04 del `REVIEW-2026-10.md`): la autenticación identifica a cada usuario, pero todavía no limita cuánto puede usar el chat. Sigue bloqueando `PROVIDER_MODE=real`.
- **Sin recuperación de contraseña** ni cambio de contraseña desde la app: por ahora lo gestiona quien administra Supabase.
- El token se guarda en `localStorage` (el comportamiento por defecto de `supabase-js`). Es aceptable porque la app no inyecta HTML (no usa `dangerouslySetInnerHTML`), pero un fallo XSS futuro lo expondría; pasar a cookies `httpOnly` es una mejora posible.
- Si Supabase rota las claves, el backend aprende la nueva en cuanto ve un `kid` desconocido, pero como máximo una vez por minuto. Si Supabase no responde, se siguen usando las claves ya descargadas.
- El panel de administración (MVP-8) todavía no existe: `require_admin` ya está listo en el backend, pero ninguna ruta lo usa aún.
