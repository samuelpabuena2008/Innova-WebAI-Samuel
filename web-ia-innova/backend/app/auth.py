"""Autenticación (MVP-1): valida el JWT que emite Supabase y dice quién es el usuario y qué rol tiene.

Flujo: el navegador inicia sesión en Supabase (correo + contraseña), recibe un access token (JWT) y lo
manda en `Authorization: Bearer <token>`. El backend NO ve la contraseña: solo comprueba que el token es
auténtico (firma), está vigente (exp), fue emitido para esta app (aud/iss) y lee el rol.

Reglas de seguridad de este módulo:
- Falla CERRADO: sin configuración, o ante cualquier duda, no se deja pasar a nadie.
- El rol sale SOLO de `app_metadata.role`, que únicamente se puede editar con la clave de servicio
  (desde el servidor). `user_metadata` lo puede editar el propio usuario desde el navegador: NUNCA se usa
  para decidir permisos.
- Los algoritmos permitidos se fijan aquí según el tipo de clave; jamás se confía en el `alg` que trae el
  token para elegir cómo verificarlo (evita "algorithm confusion" y el famoso `alg: none`).
- Al cliente no se le explica por qué se rechazó su token (401 genérico). El motivo va a los logs como un
  código corto, sin el token.
"""
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import httpx
import jwt

log = logging.getLogger("auth")

# `aud` de los tokens de usuarios con sesión iniciada en Supabase (los de la clave anónima traen "anon").
AUDIENCE = "authenticated"

# Roles de la aplicación (informe, MVP-1: "roles usuario/admin").
ROLE_USER = "usuario"
ROLE_ADMIN = "admin"

# Un JWT real de Supabase mide ~1 KB. El tope evita gastar CPU en firmas de basura gigante.
MAX_TOKEN_CHARS = 8192
# Tolerancia de reloj entre servidores (segundos) para exp / iat / nbf.
LEEWAY_S = 10

# Supabase firma hoy con claves asimétricas; las públicas se descargan de su endpoint JWKS.
ASYMMETRIC_ALGS = ("ES256", "RS256")
JWKS_TTL_S = 600.0               # Supabase cachea ese endpoint ~10 min: no tiene sentido preguntar más a menudo
JWKS_REFRESH_COOLDOWN_S = 60.0   # tope de descargas ante un `kid` desconocido (ver JwksCache)
JWKS_TIMEOUT_S = 3.0
JWKS_MAX_BYTES = 256_000


class AuthError(Exception):
    """Token rechazado (→ 401). `motivo` es un código corto para los logs; nunca se envía al cliente."""

    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


class AuthUnavailable(Exception):
    """No se pudo verificar por un problema nuestro o de Supabase, no del usuario (→ 503)."""

    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


class _JwksInesperado(ValueError):
    """Respuesta del JWKS que no sirve (estado ≠ 200, demasiado grande o mal formada). Uso interno."""


@dataclass(frozen=True)
class AuthUser:
    """Usuario autenticado. Analogía Java: un `record` inmutable con el principal de la sesión."""

    id: str                  # `sub` del token: el UUID del usuario en Supabase (no es un dato personal)
    email: Optional[str]
    role: str                # ROLE_USER o ROLE_ADMIN

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


def role_from_claims(claims: dict) -> str:
    """Rol de la aplicación a partir de los claims YA VERIFICADOS del token.

    Solo cuenta `app_metadata.role == "admin"` (coincidencia exacta). Cualquier otra cosa (ausente,
    "ADMIN", "superadmin", un valor que no sea texto, `app_metadata` que no sea un objeto) es un usuario
    normal: ante la duda, el privilegio mínimo. Se ignora `user_metadata` a propósito (lo edita el usuario).

    Nota: el claim de nivel superior `role` de Supabase vale "authenticated" y es el rol de Postgres,
    no el de la app; por eso el rol de la app vive dentro de `app_metadata`.
    """
    app_metadata = claims.get("app_metadata")
    rol = app_metadata.get("role") if isinstance(app_metadata, dict) else None
    return ROLE_ADMIN if rol == ROLE_ADMIN else ROLE_USER


class JwksCache:
    """Caché de las claves PÚBLICAS con las que Supabase firma los tokens (endpoint JWKS).

    Se descarga el conjunto de claves una vez y se reutiliza durante JWKS_TTL_S. Si llega un token con un
    `kid` que no conocemos (p. ej. Supabase rotó la clave) se vuelve a descargar, pero como máximo una vez
    cada JWKS_REFRESH_COOLDOWN_S: así un atacante que mande tokens con `kid` inventados no puede obligarnos
    a llamar a Supabase en cada petición (amplificación). Si la descarga falla se siguen usando las claves
    que ya teníamos (disponibilidad); si nunca hubo ninguna, es un problema nuestro (AuthUnavailable).

    Analogía Java: un `LoadingCache` de Guava con expiración y recarga limitada.
    `client` y `clock` se inyectan para poder probarlo sin red y sin esperar minutos reales.
    """

    def __init__(
        self,
        url: str,
        client: Optional[httpx.Client] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._url = url
        self._client = client or httpx.Client()  # httpx NO sigue redirecciones por defecto: bien
        self._clock = clock
        self._lock = threading.Lock()
        self._claves: dict[str, jwt.PyJWK] = {}   # se reemplaza entero (nunca se muta): lectura sin lock
        self._cargado_en: Optional[float] = None  # última descarga CORRECTA
        self._ultimo_intento: Optional[float] = None  # última descarga intentada (buena o mala)

    def _vigente(self, ahora: float) -> bool:
        return self._cargado_en is not None and ahora - self._cargado_en < JWKS_TTL_S

    def key_for(self, kid: str):
        """Clave pública (objeto de `cryptography`) del `kid`, o AuthError / AuthUnavailable."""
        # Camino rápido, sin lock: la clave está en caché y la caché sigue vigente.
        clave = self._claves.get(kid)
        if clave is not None and self._vigente(self._clock()):
            return clave.key

        with self._lock:
            ahora = self._clock()
            clave = self._claves.get(kid)
            if clave is not None and self._vigente(ahora):  # otro hilo ya la refrescó mientras esperábamos
                return clave.key
            if self._ultimo_intento is None or ahora - self._ultimo_intento >= JWKS_REFRESH_COOLDOWN_S:
                self._refrescar(ahora)
            clave = self._claves.get(kid)  # tras refrescar (o, si no tocaba, la copia anterior aunque esté vencida)

        if clave is not None:
            return clave.key
        if self._cargado_en is None:
            raise AuthUnavailable("jwks_no_disponible")
        raise AuthError("kid_desconocido")

    def _refrescar(self, ahora: float) -> None:
        """Descarga el JWKS. Llamar con el lock tomado. Nunca lanza: si falla, se queda lo que había."""
        self._ultimo_intento = ahora  # se anota ANTES: un fallo también cuenta para el enfriamiento
        try:
            resp = self._client.get(self._url, timeout=JWKS_TIMEOUT_S)
            if resp.status_code != 200:
                raise _JwksInesperado(f"http_{resp.status_code}")
            if len(resp.content) > JWKS_MAX_BYTES:
                raise _JwksInesperado("respuesta_demasiado_grande")
            nuevas = self._parsear(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            # Los motivos propios (_JwksInesperado) son códigos cortos y seguros. De los errores de httpx o
            # del parser JSON solo se registra el TIPO: su texto podría incluir la URL o parte del cuerpo.
            motivo = str(exc) if isinstance(exc, _JwksInesperado) else type(exc).__name__
            log.warning("jwks no se pudo descargar motivo=%s", motivo)
            return
        self._claves = nuevas
        self._cargado_en = ahora
        log.info("jwks actualizado claves=%d", len(nuevas))

    @staticmethod
    def _parsear(data: object) -> dict[str, jwt.PyJWK]:
        """Convierte el JSON del JWKS en {kid: clave}. Ignora (sin fallar) lo que no sea una clave EC/RSA."""
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise _JwksInesperado("jwks_malformado")
        claves: dict[str, jwt.PyJWK] = {}
        for jwk in data["keys"]:
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            # Solo claves públicas asimétricas: una clave simétrica ("oct") en un JWKS no debe poder
            # usarse nunca para verificar nada.
            if not isinstance(kid, str) or jwk.get("kty") not in ("EC", "RSA"):
                continue
            try:
                claves[kid] = jwt.PyJWK.from_dict(jwk)
            except (jwt.PyJWTError, ValueError, KeyError, TypeError):  # clave mal formada: se descarta
                continue
        return claves


class JwtVerifier:
    """Comprueba un access token de Supabase y devuelve el AuthUser, o lanza AuthError / AuthUnavailable.

    Acepta dos tipos de firma, y la elección la hace ESTE código, no el token:
    - ES256 / RS256 (claves asimétricas): se verifica con la clave pública del JWKS que corresponde al `kid`.
    - HS256 (secreto compartido "legado"): solo si hay secreto configurado. Supabase sigue aceptando tokens
      firmados con el secreto viejo hasta que caducan al rotar claves, y los proyectos antiguos solo usan este.
    Cualquier otro algoritmo (`none`, HS384, ES512...) se rechaza. Y la clave pública NUNCA se usa como secreto
    HMAC, ni al revés: cada rama verifica con su propia clave y con su propia lista de algoritmos.
    """

    def __init__(self, issuer: str, jwks: Optional[JwksCache] = None, hs_secret: Optional[str] = None):
        self._issuer = issuer
        self._jwks = jwks
        self._hs_secret = hs_secret or None

    def _clave_para(self, alg: object, kid: object):
        """(clave, algoritmos permitidos) para verificar un token con esa cabecera."""
        if alg == "HS256":
            if not self._hs_secret:
                raise AuthError("hs256_no_configurado")
            return self._hs_secret, ["HS256"]
        if alg in ASYMMETRIC_ALGS:
            if self._jwks is None:
                raise AuthError("jwks_no_configurado")
            if not isinstance(kid, str) or not kid:
                raise AuthError("token_sin_kid")
            return self._jwks.key_for(kid), [alg]
        raise AuthError("algoritmo_no_permitido")

    def verify(self, token: str) -> AuthUser:
        if not token or len(token) > MAX_TOKEN_CHARS:
            raise AuthError("token_invalido")
        try:
            cabecera = jwt.get_unverified_header(token)  # solo para saber `alg` y `kid`; aún NO se confía en nada
        except jwt.PyJWTError:
            raise AuthError("token_malformado") from None

        clave, algoritmos = self._clave_para(cabecera.get("alg"), cabecera.get("kid"))
        try:
            claims = jwt.decode(
                token,
                clave,
                algorithms=algoritmos,
                audience=AUDIENCE,
                issuer=self._issuer,
                leeway=LEEWAY_S,
                # PyJWT solo exige exp si viene; aquí un token sin caducidad, sin dueño o sin
                # audiencia/emisor se rechaza.
                options={"require": ["exp", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            # El nombre de la excepción (ExpiredSignatureError, InvalidSignatureError, InvalidAudienceError...)
            # sirve de motivo en los logs y no contiene el token.
            raise AuthError(type(exc).__name__) from None

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise AuthError("sin_sub")
        # Supabase permite "inicios de sesión anónimos": generan un token válido para cualquiera, sin
        # correo. El acceso a esta app es cerrado (miembros de prueba), así que se rechazan.
        if claims.get("is_anonymous") is True:
            raise AuthError("usuario_anonimo")

        email = claims.get("email")
        return AuthUser(id=sub, email=email if isinstance(email, str) else None, role=role_from_claims(claims))
