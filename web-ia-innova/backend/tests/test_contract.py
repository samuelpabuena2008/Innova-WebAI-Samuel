"""Pruebas de contrato de /orchestrate y /health con TestClient. Sin red y sin clave real."""
import os
import re
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.auth import USUARIO_DE_DESARROLLO, get_current_user
from app.main import app
from app.providers import ProviderError
from app.schemas import MAX_MESSAGE_CHARS

CAMPOS = {"request_id", "content", "model", "category", "reason", "latency_ms",
          "fallback_used", "is_mock", "decided_by"}
DECIDED_BY = {"regla", "gestora_llm", "regla_respaldo"}
FRONT_API = Path(__file__).resolve().parents[2] / "frontend" / "src" / "services" / "orchestratorApi.ts"


class ClasificadorFalso:
    enabled = True

    def __init__(self, respuesta=None):
        self.respuesta, self.llamadas = respuesta, 0

    def classify(self, text):
        self.llamadas += 1
        return self.respuesta


class TestOrchestrateContrato(unittest.TestCase):
    """El contrato de /orchestrate se prueba con un usuario ya autenticado (la autenticación en sí se
    prueba en test_auth.py y test_auth_endpoints.py). Se sustituye la dependencia de FastAPI, igual que
    se inyecta un Classifier falso."""

    def setUp(self):
        app.dependency_overrides[get_current_user] = lambda: USUARIO_DE_DESARROLLO
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app)

    def _post(self, mensaje, clasificador=None):
        with patch("app.main.get_classifier", return_value=clasificador or ClasificadorFalso()):
            return self.client.post("/orchestrate", json={"message": mensaje})

    def test_200_en_mock_con_todos_los_campos(self):
        r = self._post("Escribe un script " + "para el servidor " * 20)
        self.assertEqual(r.status_code, 200)
        cuerpo = r.json()
        self.assertEqual(set(cuerpo), CAMPOS)
        self.assertIs(cuerpo["is_mock"], True)
        self.assertIn(cuerpo["decided_by"], DECIDED_BY)
        self.assertIsInstance(cuerpo["latency_ms"], int)
        self.assertIsInstance(cuerpo["fallback_used"], bool)
        self.assertIn("SIMULADA", cuerpo["content"])

    def test_decided_by_regla_en_senal_fuerte(self):
        falso = ClasificadorFalso("tarea_breve")
        r = self._post("Hay que depurar un error " + "de concurrencia " * 20, falso)
        self.assertEqual((r.json()["decided_by"], r.json()["category"]), ("regla", "razonamiento_complejo"))
        self.assertEqual(falso.llamadas, 0)

    def test_decided_by_gestora_llm_en_mensaje_ambiguo(self):
        r = self._post("Hola", ClasificadorFalso("razonamiento_complejo"))
        self.assertEqual((r.json()["decided_by"], r.json()["category"]), ("gestora_llm", "razonamiento_complejo"))

    def test_decided_by_regla_respaldo_si_el_llm_falla(self):
        r = self._post("Hola", ClasificadorFalso(None))
        self.assertEqual((r.json()["decided_by"], r.json()["category"]), ("regla_respaldo", "tarea_breve"))

    def test_privado_no_llega_al_clasificador(self):
        falso = ClasificadorFalso("general")
        r = self._post("Resume este texto confidencial de nómina", falso)
        self.assertEqual(r.json()["category"], "procesamiento_privado")
        self.assertEqual(falso.llamadas, 0)

    def test_422_mensaje_vacio_solo_espacios_y_demasiado_largo(self):
        self.assertEqual(self._post("").status_code, 422)
        self.assertEqual(self._post("    ").status_code, 422)
        self.assertEqual(self._post("a" * (MAX_MESSAGE_CHARS + 1)).status_code, 422)
        self.assertEqual(self._post("a" * MAX_MESSAGE_CHARS).status_code, 200)

    def test_502_si_todos_los_proveedores_fallan(self):
        proveedor = MagicMock()
        proveedor.generate.side_effect = ProviderError("caído")
        with patch("app.main.get_provider", return_value=proveedor):
            r = self._post("Hola, ¿qué hora es?")
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.json(), {"detail": "Ningún proveedor disponible en este momento."})

    def test_503_privado_en_modo_real_sin_ruta_privada(self):
        proveedor = MagicMock()
        with patch.dict(os.environ, {"PROVIDER_MODE": "real"}):
            os.environ.pop("PRIVATE_ROUTE_URL", None)
            with patch("app.main.get_provider", return_value=proveedor):
                r = self._post("Esto es confidencial")
        self.assertEqual(r.status_code, 503)
        proveedor.generate.assert_not_called()


class TestCors(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def _preflight(self, cabeceras):
        return self.client.options("/orchestrate", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": cabeceras,
        })

    def test_content_type_permitido(self):
        self.assertEqual(self._preflight("Content-Type").status_code, 200)

    def test_cabecera_arbitraria_rechazada(self):
        self.assertEqual(self._preflight("X-Evil").status_code, 400)

    def test_origen_no_permitido_no_recibe_cabecera_cors(self):
        r = self.client.options("/orchestrate", headers={
            "Origin": "https://malo.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn("access-control-allow-origin", r.headers)


class TestHealth(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_en_modo_reglas_sin_clave(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["gestora_mode"], "rules")
        self.assertIs(r.json()["api_key_configured"], False)

    def test_health_hibrido_con_clave_nunca_expone_la_clave(self):
        secreto = "clave-super-secreta-xyz"
        with patch.dict(os.environ, {"GEMINI_API_KEY": secreto, "GESTORA_MODE": "hybrid"}):
            r = self.client.get("/health")
        self.assertEqual(r.json()["gestora_mode"], "hybrid")
        self.assertIs(r.json()["api_key_configured"], True)
        self.assertNotIn(secreto, r.text)

    def test_hibrido_pedido_pero_sin_clave_cae_a_reglas(self):
        with patch.dict(os.environ, {"GESTORA_MODE": "hybrid"}):
            os.environ.pop("GEMINI_API_KEY", None)
            r = self.client.get("/health")
        self.assertEqual((r.json()["gestora_mode"], r.json()["api_key_configured"]), ("rules", False))


class TestContratoConElFrontend(unittest.TestCase):
    """El contrato vive solo en orchestratorApi.ts: se comprueba que coincide con el backend."""

    @classmethod
    def setUpClass(cls):
        cls.ts = FRONT_API.read_text(encoding="utf-8")

    def test_el_frontend_solo_lee_campos_que_el_backend_devuelve(self):
        leidos = set(re.findall(r"\bd\.(\w+)", self.ts))
        # "response" es un alias tolerante del frontend; el resto debe existir en el backend.
        self.assertTrue(leidos - {"response"} <= CAMPOS, leidos - CAMPOS)

    def test_endpoint_y_cuerpo(self):
        self.assertIn('"/orchestrate"', self.ts)
        self.assertIn("JSON.stringify({ message: req.message })", self.ts)

    def test_el_frontend_envia_el_jwt_como_bearer(self):
        # MVP-1: el backend exige `Authorization: Bearer <jwt>`; si el frontend dejara de mandarla, el chat
        # real daría 401 siempre y esta prueba lo avisa antes de desplegar.
        self.assertIn("Authorization: `Bearer ${token}`", self.ts)

    def test_el_limite_de_mensaje_coincide(self):
        encontrado = re.search(r"MAX_MESSAGE_CHARS\s*=\s*([\d_]+)", self.ts)
        self.assertIsNotNone(encontrado)
        self.assertEqual(int(encontrado.group(1).replace("_", "")), MAX_MESSAGE_CHARS)


if __name__ == "__main__":
    unittest.main()
