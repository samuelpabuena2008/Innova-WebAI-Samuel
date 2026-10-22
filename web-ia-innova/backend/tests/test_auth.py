"""Pruebas de la autenticación (app/auth.py). Sin red y sin Supabase real: ver tests/auth_helpers.py."""
import base64
import hashlib
import hmac
import json
import time
import unittest

import jwt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.auth import (
    JWKS_MAX_BYTES,
    JWKS_REFRESH_COOLDOWN_S,
    JWKS_TTL_S,
    MAX_TOKEN_CHARS,
    ROLE_ADMIN,
    ROLE_USER,
    AuthError,
    AuthUnavailable,
    AuthUser,
    JwksCache,
    JwtVerifier,
    role_from_claims,
)
from tests.auth_helpers import (
    ISSUER,
    JWKS_URL,
    SECRETO_HS256,
    RelojFalso,
    SupabaseFalso,
    claims_validos,
    firmar,
    nueva_clave_ec,
)


class TestRol(unittest.TestCase):
    def test_admin_solo_con_app_metadata_role_admin_exacto(self):
        self.assertEqual(role_from_claims({"app_metadata": {"role": "admin"}}), ROLE_ADMIN)

    def test_por_defecto_es_usuario(self):
        self.assertEqual(role_from_claims({}), ROLE_USER)
        self.assertEqual(role_from_claims({"app_metadata": {}}), ROLE_USER)
        self.assertEqual(role_from_claims({"app_metadata": {"role": "usuario"}}), ROLE_USER)

    def test_user_metadata_se_ignora_porque_lo_edita_el_usuario(self):
        self.assertEqual(role_from_claims({"user_metadata": {"role": "admin"}}), ROLE_USER)

    def test_el_claim_role_de_postgres_no_da_privilegios(self):
        self.assertEqual(role_from_claims({"role": "admin"}), ROLE_USER)
        self.assertEqual(role_from_claims({"role": "service_role"}), ROLE_USER)

    def test_valores_raros_son_usuario(self):
        for raro in ("ADMIN", "Admin", " admin", "superadmin", "", None, 1, True, ["admin"], {"admin": True}):
            with self.subTest(valor=raro):
                self.assertEqual(role_from_claims({"app_metadata": {"role": raro}}), ROLE_USER)
        for no_objeto in ("admin", ["admin"], 1, None):
            with self.subTest(app_metadata=no_objeto):
                self.assertEqual(role_from_claims({"app_metadata": no_objeto}), ROLE_USER)

    def test_is_admin(self):
        self.assertTrue(AuthUser("1", None, ROLE_ADMIN).is_admin)
        self.assertFalse(AuthUser("1", None, ROLE_USER).is_admin)


class TestJwksCache(unittest.TestCase):
    def setUp(self):
        self.k1 = nueva_clave_ec()
        self.servidor = SupabaseFalso(k1=self.k1)
        self.reloj = RelojFalso()
        self.cache = JwksCache(JWKS_URL, client=self.servidor.cliente, clock=self.reloj)

    def test_devuelve_la_clave_publica_del_kid(self):
        clave = self.cache.key_for("k1")
        self.assertEqual(clave.public_numbers(), self.k1.public_key().public_numbers())

    def test_reutiliza_la_cache_sin_volver_a_descargar(self):
        for _ in range(5):
            self.cache.key_for("k1")
        self.assertEqual(self.servidor.descargas, 1)

    def test_pasado_el_ttl_vuelve_a_descargar(self):
        self.cache.key_for("k1")
        self.reloj.avanzar(JWKS_TTL_S + 1)
        self.cache.key_for("k1")
        self.assertEqual(self.servidor.descargas, 2)

    def test_kid_desconocido_es_401_y_no_descarga_mas_de_una_vez_por_enfriamiento(self):
        self.cache.key_for("k1")  # 1 descarga
        for i in range(20):  # 20 tokens con kid inventado
            with self.assertRaises(AuthError) as ctx:
                self.cache.key_for(f"inventado-{i}")
            self.assertEqual(ctx.exception.motivo, "kid_desconocido")
        # Sin el enfriamiento serían 21 descargas: el atacante nos haría llamar a Supabase en cada petición.
        self.assertLessEqual(self.servidor.descargas, 2)

    def test_rotacion_de_clave_se_aprende_tras_el_enfriamiento(self):
        self.cache.key_for("k1")
        k2 = nueva_clave_ec()
        self.servidor.publicar("k2", k2)
        with self.assertRaises(AuthError):  # dentro del enfriamiento aún no se vuelve a preguntar
            self.cache.key_for("k2")
        self.reloj.avanzar(JWKS_REFRESH_COOLDOWN_S + 1)
        clave = self.cache.key_for("k2")
        self.assertEqual(clave.public_numbers(), k2.public_key().public_numbers())

    def test_sin_clave_previa_y_supabase_caido_es_503_no_401(self):
        self.servidor.caido = True
        with self.assertRaises(AuthUnavailable):
            self.cache.key_for("k1")

    def test_si_la_descarga_falla_se_siguen_usando_las_claves_conocidas(self):
        self.cache.key_for("k1")
        self.servidor.caido = True
        self.reloj.avanzar(JWKS_TTL_S + 1)  # caché vencida, pero Supabase no responde
        self.assertIsNotNone(self.cache.key_for("k1"))

    def test_un_error_de_descarga_tambien_activa_el_enfriamiento(self):
        self.servidor.caido = True
        for _ in range(10):
            with self.assertRaises(AuthUnavailable):
                self.cache.key_for("k1")
        self.assertEqual(self.servidor.descargas, 1)

    def test_respuestas_raras_del_jwks_no_rompen_nada(self):
        grande = b'{"keys": [], "relleno": "' + b"x" * (JWKS_MAX_BYTES + 1) + b'"}'
        for cuerpo in (b"no es json", b"[]", b'{"keys": "no-es-lista"}', b'{"otra": 1}', grande):
            with self.subTest(cuerpo=cuerpo[:20]):
                servidor = SupabaseFalso(k1=self.k1)
                servidor.cuerpo_crudo = cuerpo
                cache = JwksCache(JWKS_URL, client=servidor.cliente, clock=RelojFalso())
                with self.assertRaises(AuthUnavailable):  # nunca hubo claves válidas: problema nuestro, no del usuario
                    cache.key_for("k1")

    def test_ignora_claves_simetricas_y_malformadas(self):
        self.servidor.claves["oct"] = {"kty": "oct", "kid": "oct", "k": "c2VjcmV0bw"}
        self.servidor.claves["roto"] = {"kty": "EC", "kid": "roto", "crv": "P-256", "x": "no", "y": "no"}
        self.servidor.claves["sin-kid"] = {"kty": "EC"}
        self.assertIsNotNone(self.cache.key_for("k1"))
        for kid in ("oct", "roto"):
            with self.subTest(kid=kid), self.assertRaises(AuthError):
                self.cache.key_for(kid)


def _b64(datos: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(datos).encode()).rstrip(b"=").decode()


def token_a_mano(cabecera: dict, claims: dict, firma: bytes = b"firma") -> str:
    """Token con cabecera y claims a medida (para casos que PyJWT se niega a firmar)."""
    return f"{_b64(cabecera)}.{_b64(claims)}." + base64.urlsafe_b64encode(firma).rstrip(b"=").decode()


class TestJwtVerifier(unittest.TestCase):
    def setUp(self):
        self.clave = nueva_clave_ec()
        self.servidor = SupabaseFalso(k1=self.clave)
        self.jwks = JwksCache(JWKS_URL, client=self.servidor.cliente, clock=RelojFalso())
        self.verificador = JwtVerifier(ISSUER, self.jwks)  # solo claves asimétricas
        self.con_secreto = JwtVerifier(ISSUER, self.jwks, hs_secret=SECRETO_HS256)

    def _rechaza(self, token, motivo=None, verificador=None):
        with self.assertRaises(AuthError) as ctx:
            (verificador or self.verificador).verify(token)
        if motivo is not None:
            self.assertEqual(ctx.exception.motivo, motivo)

    # --- lo que SÍ debe pasar ----------------------------------------------------------------
    def test_token_valido_devuelve_el_usuario(self):
        usuario = self.verificador.verify(firmar(self.clave))
        self.assertEqual(usuario, AuthUser("11111111-2222-3333-4444-555555555555", "ana@example.com", ROLE_USER))

    def test_admin_por_app_metadata(self):
        token = firmar(self.clave, app_metadata={"role": "admin"})
        self.assertTrue(self.verificador.verify(token).is_admin)

    def test_user_metadata_admin_no_da_privilegios(self):
        token = firmar(self.clave, user_metadata={"role": "admin"}, app_metadata={})
        self.assertEqual(self.verificador.verify(token).role, ROLE_USER)

    def test_tolera_unos_segundos_de_desfase_de_reloj(self):
        self.assertEqual(self.verificador.verify(firmar(self.clave, exp=int(time.time()) - 5)).role, ROLE_USER)

    def test_email_que_no_es_texto_queda_en_none(self):
        self.assertIsNone(self.verificador.verify(firmar(self.clave, email=12345)).email)

    def test_anonimo_false_no_estorba(self):
        self.assertEqual(self.verificador.verify(firmar(self.clave, is_anonymous=False)).role, ROLE_USER)

    # --- lo que NO debe pasar: claims --------------------------------------------------------
    def test_expirado(self):
        self._rechaza(firmar(self.clave, exp=int(time.time()) - 3600), "ExpiredSignatureError")

    def test_audiencia_incorrecta(self):
        self._rechaza(firmar(self.clave, aud="anon"), "InvalidAudienceError")

    def test_emisor_de_otro_proyecto(self):
        self._rechaza(firmar(self.clave, iss="https://otro.supabase.co/auth/v1"), "InvalidIssuerError")

    def test_faltan_claims_obligatorios(self):
        for claim in ("exp", "sub", "aud", "iss"):
            with self.subTest(claim=claim):
                self._rechaza(firmar(self.clave, **{claim: None}), "MissingRequiredClaimError")

    def test_sub_vacio(self):
        self._rechaza(firmar(self.clave, sub=""), "sin_sub")

    def test_usuario_anonimo_de_supabase(self):
        self._rechaza(firmar(self.clave, is_anonymous=True), "usuario_anonimo")

    # --- lo que NO debe pasar: firma y algoritmos ----------------------------------------------
    def test_firma_de_otra_clave(self):
        self._rechaza(firmar(nueva_clave_ec()), "InvalidSignatureError")

    def test_payload_alterado_para_subirse_a_admin(self):
        cabecera, _payload, firma = firmar(self.clave).split(".")
        claims = claims_validos(app_metadata={"role": "admin"})
        self._rechaza(f"{cabecera}.{_b64(claims)}.{firma}", "InvalidSignatureError")

    def test_algoritmo_none(self):
        sin_firma = jwt.encode(claims_validos(), key=None, algorithm="none", headers={"kid": "k1"})
        self._rechaza(sin_firma, "algoritmo_no_permitido")
        self._rechaza(token_a_mano({"alg": "none", "kid": "k1"}, claims_validos(), b""), "algoritmo_no_permitido")

    def test_otros_algoritmos_no_permitidos(self):
        for alg in ("HS384", "HS512", "ES384", "ES512", "PS256", "EdDSA", "", None, 256, ["ES256"]):
            with self.subTest(alg=alg):
                self._rechaza(token_a_mano({"alg": alg, "kid": "k1"}, claims_validos()), "algoritmo_no_permitido",
                              self.con_secreto)

    def test_cabecera_dice_rs256_pero_la_clave_es_ec(self):
        # Antes de capturar TypeError esto escapaba como un 500; un token manipulado debe dar 401.
        self._rechaza(token_a_mano({"alg": "RS256", "kid": "k1"}, claims_validos()))

    def test_confusion_de_algoritmo_clave_publica_usada_como_secreto_hmac(self):
        # El ataque clásico: firmar con HS256 usando como "secreto" la clave pública (que es pública).
        pem = self.clave.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        # PyJWT se niega a firmar así (protección), por eso el atacante lo haría a mano: HMAC-SHA256 con la PEM.
        cabecera, claims = _b64({"alg": "HS256", "kid": "k1"}), _b64(claims_validos(app_metadata={"role": "admin"}))
        firma = hmac.new(pem, f"{cabecera}.{claims}".encode(), hashlib.sha256).digest()
        falso = f"{cabecera}.{claims}." + base64.urlsafe_b64encode(firma).rstrip(b"=").decode()
        self._rechaza(falso, "hs256_no_configurado")                      # sin secreto: ni se intenta
        self._rechaza(falso, "InvalidSignatureError", self.con_secreto)  # con secreto: la firma no coincide

    def test_token_sin_kid(self):
        self._rechaza(jwt.encode(claims_validos(), self.clave, algorithm="ES256"), "token_sin_kid")

    def test_kid_desconocido(self):
        self._rechaza(firmar(self.clave, kid="otro"), "kid_desconocido")

    def test_verificador_sin_jwks(self):
        self._rechaza(firmar(self.clave), "jwks_no_configurado", JwtVerifier(ISSUER, None, SECRETO_HS256))

    # --- HS256 (secreto legado) ----------------------------------------------------------------
    def test_hs256_sin_secreto_configurado(self):
        token = jwt.encode(claims_validos(), SECRETO_HS256, algorithm="HS256")
        self._rechaza(token, "hs256_no_configurado")

    def test_hs256_con_el_secreto_correcto(self):
        token = jwt.encode(claims_validos(app_metadata={"role": "admin"}), SECRETO_HS256, algorithm="HS256")
        self.assertTrue(self.con_secreto.verify(token).is_admin)

    def test_hs256_con_secreto_equivocado(self):
        token = jwt.encode(claims_validos(), "otro-secreto-que-tambien-mide-mas-de-32-bytes", algorithm="HS256")
        self._rechaza(token, "InvalidSignatureError", self.con_secreto)

    def test_con_secreto_configurado_los_tokens_asimetricos_siguen_valiendo(self):
        self.assertEqual(self.con_secreto.verify(firmar(self.clave)).role, ROLE_USER)

    # --- entradas basura -------------------------------------------------------------------------
    def test_basura(self):
        for basura in ("", "abc", "a.b.c", "....", "x" * (MAX_TOKEN_CHARS + 1), "Bearer abc", "\x00\x01"):
            with self.subTest(token=basura[:15]):
                self._rechaza(basura)

    def test_firma_alterada(self):
        token = firmar(self.clave)
        self._rechaza(token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB"))

    # --- problemas nuestros (no del usuario) -----------------------------------------------------------
    def test_supabase_caido_sin_claves_es_503_no_401(self):
        self.servidor.caido = True
        with self.assertRaises(AuthUnavailable):
            self.verificador.verify(firmar(self.clave))


if __name__ == "__main__":
    unittest.main()
