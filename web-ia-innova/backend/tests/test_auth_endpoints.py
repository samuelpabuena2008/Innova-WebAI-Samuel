"""La autenticación aplicada a la app REAL (app.main.app): /orchestrate y /me exigen sesión de Supabase.

Sin red: el JWKS lo sirve un transporte falso (tests/auth_helpers.py) y los tokens se firman en memoria.
"""
import os
import time
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.auth import JwksCache, JwtVerifier
from app.main import app
from tests.auth_helpers import ISSUER, JWKS_URL, RelojFalso, SupabaseFalso, firmar, nueva_clave_ec

MENSAJE = {"message": "Hola, ¿qué hora es?"}


class ClasificadorFalso:
    enabled = True

    def __init__(self):
        self.llamadas = 0

    def classify(self, text):
        self.llamadas += 1
        return None


class _Base(unittest.TestCase):
    def setUp(self):
        self.clave = nueva_clave_ec()
        servidor = SupabaseFalso(k1=self.clave)
        verificador = JwtVerifier(ISSUER, JwksCache(JWKS_URL, client=servidor.cliente, clock=RelojFalso()))
        for parche in (
            patch("app.auth.get_verifier", return_value=verificador),
            patch.dict(os.environ, {"AUTH_MODE": "required", "PROVIDER_MODE": "mock"}),
        ):
            parche.start()
            self.addCleanup(parche.stop)

        # Un proveedor y un clasificador espía: si la autenticación falla, NO deben tocarse.
        self.proveedor = MagicMock()
        self.proveedor.generate.return_value = "respuesta"
        self.clasificador = ClasificadorFalso()
        for parche in (
            patch("app.main.get_provider", return_value=self.proveedor),
            patch("app.main.get_classifier", return_value=self.clasificador),
        ):
            parche.start()
            self.addCleanup(parche.stop)
        self.client = TestClient(app)

    def _cabecera(self, **cambios):
        return {"Authorization": f"Bearer {firmar(self.clave, **cambios)}"}


class TestOrchestrateProtegido(_Base):
    def _sin_efectos(self):
        """Tras un rechazo no se clasificó ni se llamó a ningún proveedor."""
        self.assertEqual(self.clasificador.llamadas, 0)
        self.proveedor.generate.assert_not_called()

    def test_sin_token_401(self):
        r = self.client.post("/orchestrate", json=MENSAJE)
        self.assertEqual((r.status_code, r.json()), (401, {"detail": "No autenticado"}))
        self.assertEqual(r.headers["www-authenticate"], "Bearer")
        self._sin_efectos()

    def test_token_invalido_o_expirado_401(self):
        for cabecera in ({"Authorization": "Bearer basura"},
                         self._cabecera(exp=int(time.time()) - 3600),
                         {"Authorization": f"Bearer {firmar(nueva_clave_ec())}"}):
            with self.subTest(cabecera=cabecera["Authorization"][:30]):
                self.assertEqual(self.client.post("/orchestrate", json=MENSAJE, headers=cabecera).status_code, 401)
        self._sin_efectos()

    def test_sin_token_gana_el_401_aunque_el_cuerpo_sea_invalido(self):
        # Un anónimo no debe poder sondear las reglas de validación: primero identidad, luego cuerpo.
        r = self.client.post("/orchestrate", json={"message": ""})
        self.assertEqual(r.status_code, 401)

    def test_con_token_valido_200(self):
        r = self.client.post("/orchestrate", json=MENSAJE, headers=self._cabecera())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["content"], "respuesta")
        self.proveedor.generate.assert_called_once()

    def test_con_token_valido_el_cuerpo_invalido_sigue_dando_422(self):
        r = self.client.post("/orchestrate", json={"message": "   "}, headers=self._cabecera())
        self.assertEqual(r.status_code, 422)

    def test_usuario_y_admin_pueden_usar_el_chat(self):
        for app_metadata in ({}, {"role": "admin"}):
            with self.subTest(app_metadata=app_metadata):
                r = self.client.post("/orchestrate", json=MENSAJE, headers=self._cabecera(app_metadata=app_metadata))
                self.assertEqual(r.status_code, 200)

    def test_el_log_lleva_el_usuario_pero_nunca_el_token_ni_el_correo(self):
        cabecera = self._cabecera()
        token = cabecera["Authorization"].split(" ")[1]
        with self.assertLogs(level="INFO") as registro:
            self.client.post("/orchestrate", json=MENSAJE, headers=cabecera)
            self.client.post("/orchestrate", json=MENSAJE, headers={"Authorization": f"Bearer {token[:-3]}xyz"})
        texto = "\n".join(registro.output)
        self.assertIn("user=11111111-2222-3333-4444-555555555555", texto)
        self.assertIn("auth rechazada motivo=", texto)
        self.assertNotIn(token, texto)
        self.assertNotIn(token[:-3], texto)
        self.assertNotIn("ana@example.com", texto)


class TestMe(_Base):
    def test_sin_token_401(self):
        self.assertEqual(self.client.get("/me").status_code, 401)

    def test_usuario(self):
        r = self.client.get("/me", headers=self._cabecera())
        self.assertEqual(r.json(), {"id": "11111111-2222-3333-4444-555555555555",
                                    "email": "ana@example.com", "role": "usuario"})

    def test_admin(self):
        r = self.client.get("/me", headers=self._cabecera(app_metadata={"role": "admin"}))
        self.assertEqual(r.json()["role"], "admin")

    def test_el_rol_no_se_puede_pedir_desde_el_cliente(self):
        # Ni por query ni por cabecera: el rol sale únicamente del token verificado.
        r = self.client.get("/me?role=admin", headers={**self._cabecera(), "X-Role": "admin"})
        self.assertEqual(r.json()["role"], "usuario")


class TestRutasPublicas(_Base):
    def test_health_no_pide_token(self):
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_preflight_cors_con_authorization_no_pide_token_y_se_permite(self):
        r = self.client.options("/orchestrate", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization, content-type",
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("authorization", r.headers["access-control-allow-headers"].lower())


class TestModoDesarrollo(_Base):
    def test_disabled_con_mock_funciona_sin_token(self):
        with patch.dict(os.environ, {"AUTH_MODE": "disabled", "PROVIDER_MODE": "mock"}):
            self.assertEqual(self.client.post("/orchestrate", json=MENSAJE).status_code, 200)
            self.assertEqual(self.client.get("/me").json()["id"], "dev-local")

    def test_disabled_con_proveedores_reales_se_rechaza(self):
        with patch.dict(os.environ, {"AUTH_MODE": "disabled", "PROVIDER_MODE": "real"}):
            r = self.client.post("/orchestrate", json=MENSAJE)
        self.assertEqual(r.status_code, 503)
        self.proveedor.generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
