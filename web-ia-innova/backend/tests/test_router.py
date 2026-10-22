"""Casos mínimos del informe (sección 16.1). Se ejecutan con: python -m unittest -v"""
import unittest

from app.auth import USUARIO_DE_DESARROLLO  # estas pruebas llaman a orchestrate() directo: ya "autenticado"
from app.router import (CLAUDE, LONG_CONTEXT_CHARS, LUNA, NEMOTRON, RULES, SHORT_TASK_CHARS, SOL, TERRA,
                        choose_route, fallback_models)


class TestRouter(unittest.TestCase):
    def test_razonamiento_complejo_va_a_sol(self):
        self.assertEqual(choose_route("Necesito depurar un error intermitente de concurrencia en mi servicio").model, SOL)

    def test_tarea_breve_va_a_luna(self):
        self.assertEqual(choose_route("¿Qué horario de atención tienen?").model, LUNA)

    def test_contexto_largo_va_a_claude(self):
        self.assertEqual(choose_route("a" * 9000).model, CLAUDE)

    def test_repositorio_va_a_claude(self):
        self.assertEqual(choose_route("Revisa este código del repositorio y busca relaciones entre módulos, por favor").model, CLAUDE)

    def test_automatizacion_va_a_terra(self):
        msg = "Necesito que me ayudes a crear un script que automatice la descarga diaria de reportes del servidor"
        self.assertEqual(choose_route(msg).model, TERRA)

    def test_lote_privado_va_a_nemotron(self):
        self.assertEqual(choose_route("Procesar un lote de documentos confidencial que no debe salir de la infraestructura").model, NEMOTRON)

    def test_reglas_contradictorias_son_deterministas(self):
        # Coincide con privacidad (10) y con razonamiento complejo (30): gana la de menor número.
        msg = "Audita la arquitectura de este sistema con datos sensibles"
        first = choose_route(msg)
        self.assertEqual(first.model, NEMOTRON)
        self.assertEqual(first, choose_route(msg))

    def test_fallback_excluye_modelo_fallido(self):
        self.assertNotIn(TERRA, fallback_models("general", TERRA))
        self.assertTrue(len(fallback_models("razonamiento_complejo", SOL)) > 0)

    def test_fallback_orden_exacto(self):
        self.assertEqual(fallback_models("general", TERRA), [CLAUDE, NEMOTRON])
        self.assertEqual(fallback_models("razonamiento_complejo", SOL), [TERRA, CLAUDE, NEMOTRON])


class TestNormalizacion(unittest.TestCase):
    """R-02: tildes y mayúsculas no deben dejar escapar un texto privado."""

    def test_sin_tilde_sigue_siendo_privado(self):
        self.assertEqual(choose_route("informacion privada del cliente").category, "procesamiento_privado")

    def test_tilde_descompuesta_nfd_sigue_siendo_privado(self):
        self.assertEqual(choose_route("información privada del cliente").category, "procesamiento_privado")

    def test_mayusculas_con_tilde_son_privado(self):
        self.assertEqual(choose_route("INFORMACIÓN PRIVADA del cliente").category, "procesamiento_privado")


def _largo(texto: str) -> str:
    """Rellena con palabras neutras hasta pasar SHORT_TASK_CHARS, para que no gane 'tarea_breve'."""
    return texto + " " + "texto neutro " * 20


class TestPalabraCompleta(unittest.TestCase):
    """R-03: una palabra clave solo cuenta si es una palabra completa, no un trozo de otra."""

    def test_capital_no_activa_api(self):
        self.assertEqual(choose_route(_largo("¿Cuál es la capital de Francia?")).category, "general")

    def test_terapia_y_rapidez_no_activan_api(self):
        self.assertEqual(choose_route(_largo("hablemos de terapia y rapidez")).category, "general")

    def test_pilote_no_activa_lote(self):
        self.assertEqual(choose_route(_largo("El pilote de cimentación del puente")).category, "general")

    def test_loteria_no_activa_lote(self):
        self.assertEqual(choose_route(_largo("Resultados de la lotería de hoy")).category, "general")

    def test_pilote_no_le_gana_a_depurar(self):
        self.assertEqual(choose_route(_largo("Quiero depurar el pilote")).category, "razonamiento_complejo")

    def test_plurales_siguen_coincidiendo(self):
        self.assertEqual(choose_route(_largo("Procesa estos lotes de facturas")).category, "trabajo_masivo")
        self.assertEqual(choose_route(_largo("Documenta estas apis internas")).category, "automatizacion_cotidiana")

    def test_verbos_conjugados_siguen_coincidiendo(self):
        self.assertEqual(choose_route(_largo("Quiero automatizar esta tarea")).category, "automatizacion_cotidiana")
        self.assertEqual(choose_route(_largo("Redactar un mensaje formal")).category, "automatizacion_cotidiana")


class TestVocabularioPrivado(unittest.TestCase):
    """R-07: términos que deben activar la regla 10 (procesamiento_privado), uno por prueba."""

    def _es_privado(self, frase: str) -> bool:
        return choose_route(_largo(frase)).category == "procesamiento_privado"

    def test_sensible(self):
        self.assertTrue(self._es_privado("Este dato es sensible"))

    def test_datos_privados(self):
        self.assertTrue(self._es_privado("Revisa los datos privados del cliente"))

    def test_contrasena(self):
        self.assertTrue(self._es_privado("Mi contraseña es 1234"))
        self.assertTrue(self._es_privado("Mi contrasena es 1234"))

    def test_historia_clinica(self):
        self.assertTrue(self._es_privado("Resume la historia clínica del paciente"))
        self.assertTrue(self._es_privado("Resume las historias clinicas"))

    def test_cedula(self):
        self.assertTrue(self._es_privado("Mi cédula es 123456"))

    def test_numero_de_cuenta(self):
        self.assertTrue(self._es_privado("Mi número de cuenta es 998877"))

    def test_nomina(self):
        self.assertTrue(self._es_privado("Resume esta nómina"))

    def test_falso_positivo_cae_en_ruta_privada(self):
        # Decisión de diseño: ante la duda se prefiere la ruta controlada (conservador).
        self.assertTrue(self._es_privado("Esto NO es confidencial, es una consulta pública"))

    def test_palabra_parecida_no_activa(self):
        self.assertFalse(self._es_privado("Hablemos de la sensibilidad del sensor"))


class TestFallbackPrivado(unittest.TestCase):
    """R-01: lo privado NUNCA se reenvía a un proveedor externo como respaldo."""

    def test_fallback_de_categoria_privada_es_vacio(self):
        self.assertEqual(fallback_models("procesamiento_privado", NEMOTRON), [])

    def test_privado_sin_externos_aunque_falle_otro_modelo(self):
        for externo in (TERRA, CLAUDE, SOL, LUNA):
            self.assertNotIn(externo, fallback_models("procesamiento_privado", NEMOTRON))

    def test_flujo_privado_que_falla_termina_en_502_sin_reenviar(self):
        from unittest.mock import MagicMock, patch

        from fastapi import HTTPException

        from app.main import orchestrate
        from app.providers import ProviderError
        from app.schemas import OrchestrateRequest

        proveedor = MagicMock()
        proveedor.generate.side_effect = ProviderError("caído")
        with patch("app.main.get_provider", return_value=proveedor):
            with self.assertRaises(HTTPException) as ctx:
                orchestrate(OrchestrateRequest(message="Resume este texto confidencial de nómina"),
                            user=USUARIO_DE_DESARROLLO)
        self.assertEqual(ctx.exception.status_code, 502)
        # Solo se intentó el modelo controlado: el texto no salió a ningún otro proveedor.
        self.assertEqual(proveedor.generate.call_count, 1)
        self.assertEqual(proveedor.generate.call_args.args[0], NEMOTRON)


class TestBordesYCategorias(unittest.TestCase):
    """Q-03 / R-06: bordes de longitud, categoría por regla, precedencias y prioridades."""

    def test_borde_tarea_breve(self):
        self.assertEqual(choose_route("x" * (SHORT_TASK_CHARS - 1)).category, "tarea_breve")
        self.assertEqual(choose_route("x" * SHORT_TASK_CHARS).category, "general")

    def test_borde_contexto_extenso(self):
        self.assertEqual(choose_route("x" * LONG_CONTEXT_CHARS).category, "general")
        self.assertEqual(choose_route("x" * (LONG_CONTEXT_CHARS + 1)).category, "contexto_extenso")

    def test_general_va_a_terra(self):
        d = choose_route("x" * 300)
        self.assertEqual((d.category, d.model), ("general", TERRA))

    def test_categoria_por_regla_aislada(self):
        casos = {
            "procesamiento_privado": "Esto es confidencial",
            "trabajo_masivo": _largo("Procesa miles de registros"),
            "razonamiento_complejo": _largo("Revisa la arquitectura"),
            "contexto_extenso": _largo("Mira el repositorio"),
            "automatizacion_cotidiana": _largo("Escribe un script"),
        }
        for categoria, msg in casos.items():
            with self.subTest(categoria=categoria):
                self.assertEqual(choose_route(msg).category, categoria)

    def test_privado_gana_incluso_con_contexto_largo(self):
        self.assertEqual(choose_route("x" * 9000 + " confidencial").category, "procesamiento_privado")

    def test_masivo_gana_a_automatizacion(self):
        self.assertEqual(choose_route(_largo("Procesa este lote con una api")).category, "trabajo_masivo")

    def test_prioridades_son_unicas(self):
        self.assertEqual(len({r.priority for r in RULES}), len(RULES))

    def test_resultado_es_determinista_ante_mayusculas(self):
        self.assertEqual(choose_route(_largo("PROCESA ESTE LOTE")).category, "trabajo_masivo")


class TestRobustezPrivacidad(unittest.TestCase):
    """Auditoría de seguridad: texto pegado de PDF/Word y derivados no deben saltarse la regla 10."""

    def _es_privado(self, frase: str) -> bool:
        return choose_route(_largo(frase)).category == "procesamiento_privado"

    def test_guion_suave_dentro_de_la_palabra(self):
        self.assertTrue(self._es_privado("Esto es confi" + chr(0xAD) + "dencial"))

    def test_caracteres_de_ancho_cero(self):
        for codigo in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
            with self.subTest(codigo=hex(codigo)):
                self.assertTrue(self._es_privado("Esto es confi" + chr(codigo) + "dencial"))

    def test_saltos_de_linea_tabs_y_dobles_espacios_en_frases(self):
        salto, tab = chr(10), chr(9)
        self.assertTrue(self._es_privado("Resume la historia" + salto + "clinica"))
        self.assertTrue(self._es_privado("Mi numero" + tab + "de cuenta"))
        self.assertTrue(self._es_privado("Mira la informacion  privada"))

    def test_derivados_de_confidencial(self):
        self.assertTrue(self._es_privado("Hablemos de la confidencialidad del cliente"))
        self.assertTrue(self._es_privado("Te lo digo confidencialmente"))

    def test_contrasena_pegada_a_guion_bajo_o_digitos(self):
        self.assertTrue(self._es_privado("mi_contraseña es x"))
        self.assertTrue(self._es_privado("contraseña123"))

    def test_credenciales(self):
        self.assertTrue(self._es_privado("Estas son mis credenciales de acceso"))


class TestHomoglifos(unittest.TestCase):
    """P-01: letras cirílicas/griegas que imitan letras latinas no deben esquivar la regla 10."""

    def _categoria(self, frase: str) -> str:
        return choose_route(_largo(frase)).category

    def test_o_cirilica_dentro_de_confidencial(self):
        self.assertEqual(self._categoria("Esto es c" + chr(0x43E) + "nfidencial"), "procesamiento_privado")

    def test_o_griega_dentro_de_confidencial(self):
        self.assertEqual(self._categoria("Esto es c" + chr(0x3BF) + "nfidencial"), "procesamiento_privado")

    def test_mayuscula_cirilica_dentro_de_palabra_latina(self):
        self.assertEqual(self._categoria("Esto es C" + chr(0x41E) + "NFIDENCIAL"), "procesamiento_privado")

    def test_palabra_mixta_cualquiera_falla_seguro(self):
        # Una palabra que mezcla escrituras es sospechosa aunque no sea una palabra clave.
        self.assertEqual(self._categoria("Hola ma" + chr(0x440) + "ana"), "procesamiento_privado")

    def test_guion_suave_y_ancho_cero_siguen_detectandose(self):
        self.assertEqual(self._categoria("confi" + chr(0x200B) + "dencial"), "procesamiento_privado")

    def test_mensaje_normal_en_ruso_no_es_privado(self):
        ruso = "".join(chr(c) for c in (
            0x41F, 0x440, 0x438, 0x432, 0x435, 0x442, 0x2C, 0x20, 0x43A, 0x430, 0x43A, 0x20,
            0x434, 0x435, 0x43B, 0x430, 0x3F))  # "Привет, как дела?"
        self.assertNotEqual(choose_route(ruso).category, "procesamiento_privado")
        self.assertNotEqual(self._categoria(ruso + " " + ruso), "procesamiento_privado")

    def test_escrituras_distintas_en_palabras_distintas_no_son_privado(self):
        ruso = "".join(chr(c) for c in (0x43A, 0x430, 0x43A, 0x20, 0x434, 0x435, 0x43B, 0x430))  # "как дела"
        self.assertNotEqual(self._categoria("Hola " + ruso + " amigos"), "procesamiento_privado")


class TestRutaPrivadaFalloCerrado(unittest.TestCase):
    """P-02: en modo real, sin PRIVATE_ROUTE_URL lo privado responde 503 y NO llama a ningún proveedor."""

    def _llamar(self, entorno: dict, mensaje: str = "Resume este texto confidencial"):
        import os
        from unittest.mock import MagicMock, patch

        from app.main import orchestrate
        from app.schemas import OrchestrateRequest

        proveedor = MagicMock()
        proveedor.generate.return_value = "ok"
        with patch.dict(os.environ, entorno):
            if "PRIVATE_ROUTE_URL" not in entorno:
                os.environ.pop("PRIVATE_ROUTE_URL", None)
            with patch("app.main.get_provider", return_value=proveedor):
                try:
                    resp = orchestrate(OrchestrateRequest(message=mensaje), user=USUARIO_DE_DESARROLLO)
                except Exception as exc:  # HTTPException
                    return proveedor, exc
        return proveedor, resp

    def test_real_sin_ruta_privada_da_503_y_no_llama_a_nadie(self):
        from fastapi import HTTPException

        proveedor, resultado = self._llamar({"PROVIDER_MODE": "real"})
        self.assertIsInstance(resultado, HTTPException)
        self.assertEqual(resultado.status_code, 503)
        self.assertEqual(resultado.detail, "Ruta privada no disponible todavía")
        proveedor.generate.assert_not_called()

    def test_real_con_ruta_privada_configurada_si_llama(self):
        proveedor, resultado = self._llamar({"PROVIDER_MODE": "real", "PRIVATE_ROUTE_URL": "https://privado.example"})
        self.assertEqual(resultado.category, "procesamiento_privado")
        self.assertEqual(proveedor.generate.call_args.args[0], NEMOTRON)

    def test_mock_no_exige_ruta_privada(self):
        proveedor, resultado = self._llamar({"PROVIDER_MODE": "mock"})
        self.assertTrue(resultado.is_mock)

    def test_real_sin_ruta_privada_no_afecta_a_lo_no_privado(self):
        proveedor, resultado = self._llamar({"PROVIDER_MODE": "real"}, mensaje="Hola, ¿qué hora es?")
        self.assertEqual(resultado.category, "tarea_breve")


if __name__ == "__main__":
    unittest.main()
