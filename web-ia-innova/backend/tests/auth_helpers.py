"""Ayudas para probar la autenticación SIN red y SIN Supabase real.

Se generan claves ES256 en memoria, se firman tokens iguales a los de Supabase y se sirve su JWKS con un
transporte falso de httpx. (No empieza por `test` a propósito: unittest no lo recoge como pruebas.)
"""
import time

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

PROYECTO = "https://proyecto-de-prueba.supabase.co"
ISSUER = f"{PROYECTO}/auth/v1"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
SECRETO_HS256 = "secreto-legado-de-prueba-que-mide-mas-de-32-bytes"


def nueva_clave_ec() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def jwk_publica(clave: ec.EllipticCurvePrivateKey, kid: str) -> dict:
    """La clave pública en el formato JWK que publica Supabase."""
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(clave.public_key(), as_dict=True)
    return {**jwk, "kid": kid, "use": "sig", "alg": "ES256"}


def claims_validos(**cambios) -> dict:
    """Claims de un usuario normal con sesión iniciada. `cambios` pisa o añade campos."""
    ahora = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "authenticated",
        "sub": "11111111-2222-3333-4444-555555555555",
        "email": "ana@example.com",
        "role": "authenticated",
        "iat": ahora,
        "exp": ahora + 3600,
        "app_metadata": {"provider": "email"},
        "user_metadata": {},
    }
    claims.update(cambios)
    return {k: v for k, v in claims.items() if v is not None}  # None = "quita este claim"


def firmar(clave, kid: str = "k1", alg: str = "ES256", **cambios) -> str:
    return jwt.encode(claims_validos(**cambios), clave, algorithm=alg, headers={"kid": kid})


class SupabaseFalso:
    """Servidor JWKS falso: cuenta las descargas y deja cambiar las claves o simular una caída."""

    def __init__(self, **claves_por_kid):
        self.claves = {kid: jwk_publica(c, kid) for kid, c in claves_por_kid.items()}
        self.descargas = 0
        self.caido = False
        self.cuerpo_crudo = None  # si se define, se devuelve tal cual (para probar respuestas raras)
        self.cliente = httpx.Client(transport=httpx.MockTransport(self._responder))

    def publicar(self, kid: str, clave) -> None:
        self.claves[kid] = jwk_publica(clave, kid)

    def _responder(self, request: httpx.Request) -> httpx.Response:
        self.descargas += 1
        if self.caido:
            return httpx.Response(503, json={"error": "caido"})
        if self.cuerpo_crudo is not None:
            return httpx.Response(200, content=self.cuerpo_crudo)
        return httpx.Response(200, json={"keys": list(self.claves.values())})


class RelojFalso:
    """Reloj que solo avanza cuando la prueba lo manda (para probar TTL y enfriamiento sin esperar)."""

    def __init__(self, inicio: float = 1000.0):
        self.ahora = inicio

    def __call__(self) -> float:
        return self.ahora

    def avanzar(self, segundos: float) -> None:
        self.ahora += segundos
