"""Pruebas de la autenticación (app/auth.py). Sin red y sin Supabase real: ver tests/auth_helpers.py."""
import unittest

from app.auth import (
    JWKS_MAX_BYTES,
    JWKS_REFRESH_COOLDOWN_S,
    JWKS_TTL_S,
    ROLE_ADMIN,
    ROLE_USER,
    AuthError,
    AuthUnavailable,
    AuthUser,
    JwksCache,
    role_from_claims,
)
from tests.auth_helpers import JWKS_URL, RelojFalso, SupabaseFalso, nueva_clave_ec


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


if __name__ == "__main__":
    unittest.main()
