"""Endurecimiento tras la auditoría de seguridad de P-01 y P-02. Sin red."""
import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.auth import USUARIO_DE_DESARROLLO  # llamada directa a orchestrate(): ya "autenticado"
from app.main import orchestrate
from app.router import choose_route
from app.schemas import OrchestrateRequest


def _largo(texto: str) -> str:
    return texto + " " + "texto neutro " * 20


def _cat(frase: str) -> str:
    return choose_route(_largo(frase)).category


class TestPalabraPartidaPorGuion(unittest.TestCase):
    def test_guion_al_final_de_linea(self):
        self.assertEqual(_cat("Esto es confiden-" + chr(10) + "cial"), "procesamiento_privado")

    def test_guion_tipografico_y_retorno_de_carro(self):
        self.assertEqual(_cat("Esto es confiden" + chr(0x2010) + chr(13) + chr(10) + "cial"), "procesamiento_privado")

    def test_guion_con_espacios_alrededor_no_une_palabras(self):
        # "texto - lista" son palabras distintas: no debe fabricar una palabra clave.
        self.assertEqual(_cat("confi - dencial"), "general")


class TestInvisiblesQueNoSonCf(unittest.TestCase):
    def test_caracteres_ignorables(self):
        for codigo in (0x3164, 0x115F, 0xFFA0, 0x2800, 0xFE0F, 0xFE00, 0x034F):
            with self.subTest(codigo=hex(codigo)):
                self.assertEqual(_cat("Esto es confi" + chr(codigo) + "dencial"), "procesamiento_privado")


class TestSimbolosCientificosNoSonHomoglifos(unittest.TestCase):
    def test_unidades_y_letras_griegas_de_ciencia(self):
        micro, ohm_signo = chr(0xB5), chr(0x2126)  # U+00B5 (micro) y U+2126 (signo de ohmio)
        casos = ["5 " + micro + "g por kg", "3" + micro + "m de espesor", "10 k" + ohm_signo + " de resistencia",
                 "10 k" + chr(0x3A9) + " de resistencia", chr(0x394) + "x y " + chr(0x394) + "t",
                 chr(0x3BB) + "max medido", chr(0x3C0) + "r al cuadrado"]
        for frase in casos:
            with self.subTest(frase=frase):
                self.assertNotEqual(_cat(frase), "procesamiento_privado")

    def test_omicron_griega_dentro_de_palabra_sigue_detectandose(self):
        self.assertEqual(_cat("Esto es c" + chr(0x3BF) + "nfidencial"), "procesamiento_privado")


class TestRutaPrivadaValidada(unittest.TestCase):
    def _llamar(self, url):
        proveedor = MagicMock()
        proveedor.generate.return_value = "ok"
        entorno = {"PROVIDER_MODE": "real"}
        if url is not None:
            entorno["PRIVATE_ROUTE_URL"] = url
        with patch.dict(os.environ, entorno):
            if url is None:
                os.environ.pop("PRIVATE_ROUTE_URL", None)
            with patch("app.main.get_provider", return_value=proveedor), \
                    patch("app.main.get_classifier", return_value=None):
                try:
                    orchestrate(OrchestrateRequest(message="Esto es confidencial"), user=USUARIO_DE_DESARROLLO)
                    return proveedor, None
                except HTTPException as exc:
                    return proveedor, exc

    def test_url_invalida_da_503(self):
        for url in (None, "", "   ", "x", "http://inseguro.example", "ftp://x"):
            with self.subTest(url=url):
                proveedor, error = self._llamar(url)
                self.assertEqual(error.status_code, 503)
                proveedor.generate.assert_not_called()

    def test_url_https_valida_pasa(self):
        proveedor, error = self._llamar("  https://privado.example  ")
        self.assertIsNone(error)
        proveedor.generate.assert_called_once()


class TestModoRealUnico(unittest.TestCase):
    def test_main_y_proveedor_deciden_igual(self):
        from app.providers import MockProvider, RealProvider, get_provider, modo_real

        for valor, esperado_real in (("real", True), ("REAL", True), (" real", False), ("real ", False),
                                     ("mock", False), ("", False), ("prod", False)):
            with self.subTest(valor=valor), patch.dict(os.environ, {"PROVIDER_MODE": valor}):
                self.assertEqual(modo_real(), esperado_real)
                self.assertIsInstance(get_provider(), RealProvider if esperado_real else MockProvider)


class TestElCodigoNoCargaDotenv(unittest.TestCase):
    """A-04: el código NO lee .env por su cuenta; en local lo carga `uvicorn --env-file .env`."""

    def test_main_no_usa_dotenv_ni_app_env(self):
        from pathlib import Path

        import app.main

        fuente = Path(app.main.__file__).read_text(encoding="utf-8")
        self.assertNotIn("dotenv", fuente)
        self.assertNotIn("APP_ENV", fuente)


if __name__ == "__main__":
    unittest.main()
