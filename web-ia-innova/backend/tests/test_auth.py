"""Pruebas de la autenticación (app/auth.py). Sin red y sin Supabase real: ver tests/auth_helpers.py."""
import base64
import hashlib
import hmac
import itertools
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

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
    _issuer_desde_entorno,
    auth_mode,
    get_current_user,
    get_verifier,
    require_admin,
    role_from_claims,
)
from tests.auth_helpers import (
    ISSUER,
    JWKS_URL,
    PROYECTO,
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

    def test_un_estado_de_error_no_se_acepta_aunque_el_cuerpo_traiga_claves_validas(self):
        # Un 500 (o un 404 de un proxy) con un cuerpo parecido a un JWKS no debe tomarse por las claves de Supabase.
        for estado in (201, 301, 404, 500):
            with self.subTest(estado=estado):
                servidor = SupabaseFalso(k1=self.k1)
                servidor.estado_con_claves = estado
                cache = JwksCache(JWKS_URL, client=servidor.cliente, clock=RelojFalso())
                with self.assertRaises(AuthUnavailable):
                    cache.key_for("k1")

    def test_el_log_de_un_fallo_de_red_no_filtra_la_url_ni_el_texto_del_error(self):
        servidor = SupabaseFalso(k1=self.k1)
        servidor.excepcion = httpx.ConnectError("no conecta con https://secreto.example/auth/v1?apikey=ABC123")
        cache = JwksCache(JWKS_URL, client=servidor.cliente, clock=RelojFalso())
        with self.assertLogs("auth", level="WARNING") as registro, self.assertRaises(AuthUnavailable):
            cache.key_for("k1")
        texto = "\n".join(registro.output)
        self.assertIn("ConnectError", texto)           # el TIPO sí se registra: sirve para diagnosticar
        self.assertNotIn("secreto.example", texto)      # la URL y el texto del error, no
        self.assertNotIn("ABC123", texto)

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


class TestJwksCacheConcurrencia(unittest.TestCase):
    """Varios hilos a la vez (FastAPI ejecuta cada petición en un hilo del pool). Con reloj real y una descarga
    lenta, sin el candado todos verían la caché vacía a la vez y cada uno descargaría el JWKS."""

    HILOS = 32

    def _en_paralelo(self, tarea):
        barrera = threading.Barrier(self.HILOS)
        resultados, errores = [], []

        def envoltorio():
            barrera.wait()  # todos arrancan en el mismo instante
            try:
                resultados.append(tarea())
            except BaseException as exc:  # noqa: BLE001
                errores.append(exc)

        hilos = [threading.Thread(target=envoltorio) for _ in range(self.HILOS)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join(timeout=20)
        return resultados, errores

    def test_cache_fria_y_mismo_kid_provoca_una_sola_descarga(self):
        servidor = SupabaseFalso(k1=nueva_clave_ec())
        servidor.latencia = 0.1
        cache = JwksCache(JWKS_URL, client=servidor.cliente)
        resultados, errores = self._en_paralelo(lambda: cache.key_for("k1") is not None)
        self.assertEqual(errores, [])
        self.assertEqual(sum(resultados), self.HILOS)
        self.assertEqual(servidor.descargas, 1)

    def test_cache_fria_y_kids_inventados_provoca_una_sola_descarga(self):
        servidor = SupabaseFalso(k1=nueva_clave_ec())
        servidor.latencia = 0.1
        cache = JwksCache(JWKS_URL, client=servidor.cliente)
        contador = itertools.count()
        resultados, errores = self._en_paralelo(lambda: cache.key_for(f"inventado-{next(contador)}"))
        self.assertEqual(resultados, [])
        self.assertEqual({type(e) for e in errores}, {AuthError})
        self.assertEqual(len(errores), self.HILOS)
        self.assertEqual(servidor.descargas, 1)

    def test_verificador_en_paralelo_no_mezcla_identidades(self):
        clave = nueva_clave_ec()
        servidor = SupabaseFalso(k1=clave)
        servidor.latencia = 0.1
        verificador = JwtVerifier(ISSUER, JwksCache(JWKS_URL, client=servidor.cliente))
        tokens = [firmar(clave, sub=f"usuario-{i}", app_metadata={"role": "admin"} if i % 2 else {})
                  for i in range(self.HILOS)]
        indice = itertools.count()

        def verificar():
            i = next(indice)
            usuario = verificador.verify(tokens[i])
            return usuario.id == f"usuario-{i}" and usuario.is_admin == bool(i % 2)

        resultados, errores = self._en_paralelo(verificar)
        self.assertEqual(errores, [])
        self.assertTrue(all(resultados) and len(resultados) == self.HILOS)


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

    def test_un_token_valido_pero_sobredimensionado_se_rechaza(self):
        # La basura gigante ya fallaría por mal formada; esto prueba el tope con un token BIEN firmado.
        grande = firmar(self.clave, relleno="x" * MAX_TOKEN_CHARS)
        self.assertGreater(len(grande), MAX_TOKEN_CHARS)
        self._rechaza(grande, "token_invalido")
        self.assertEqual(self.verificador.verify(firmar(self.clave)).role, ROLE_USER)  # el normal sigue pasando

    def test_firma_alterada(self):
        token = firmar(self.clave)
        self._rechaza(token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB"))

    # --- problemas nuestros (no del usuario) -----------------------------------------------------------
    def test_supabase_caido_sin_claves_es_503_no_401(self):
        self.servidor.caido = True
        with self.assertRaises(AuthUnavailable):
            self.verificador.verify(firmar(self.clave))


# ---------------------------------------------------------------------------------------------
# Configuración y dependencias de FastAPI
# ---------------------------------------------------------------------------------------------
def _app_de_prueba() -> FastAPI:
    """Mini-app con una ruta para cualquier usuario y otra solo para admin (MVP-8 aún no la tiene)."""
    app = FastAPI()

    @app.get("/quien")
    def quien(usuario: AuthUser = Depends(get_current_user)):
        return {"id": usuario.id, "role": usuario.role}

    @app.get("/solo-admin")
    def solo_admin(_admin: AuthUser = Depends(require_admin)):
        return {"ok": True}

    return app


class TestAuthMode(unittest.TestCase):
    def test_por_defecto_es_required(self):
        with patch.dict(os.environ):
            os.environ.pop("AUTH_MODE", None)
            self.assertEqual(auth_mode(), "required")

    def test_solo_disabled_exacto_la_apaga(self):
        for valor, esperado in (("disabled", "disabled"), ("DISABLED", "disabled"), ("Disabled", "disabled"),
                                (" disabled", "required"), ("disabled ", "required"), ("off", "required"),
                                ("false", "required"), ("0", "required"), ("", "required"),
                                ("required", "required"), ("desactivado", "required")):
            with self.subTest(valor=valor), patch.dict(os.environ, {"AUTH_MODE": valor}):
                self.assertEqual(auth_mode(), esperado)


class TestSupabaseUrl(unittest.TestCase):
    def _issuer(self, url):
        with patch.dict(os.environ, {"SUPABASE_URL": url}):
            return _issuer_desde_entorno()

    def test_urls_validas(self):
        self.assertEqual(self._issuer("https://abc.supabase.co"), "https://abc.supabase.co/auth/v1")
        self.assertEqual(self._issuer("  https://abc.supabase.co/  "), "https://abc.supabase.co/auth/v1")
        self.assertEqual(self._issuer("http://127.0.0.1:54321"), "http://127.0.0.1:54321/auth/v1")
        self.assertEqual(self._issuer("http://localhost:54321"), "http://localhost:54321/auth/v1")

    def test_urls_rechazadas(self):
        for url in ("", "   ", "abc.supabase.co", "http://abc.supabase.co", "ftp://abc.supabase.co",
                    "http://localhost.evil.com", "https://user:pw@abc.supabase.co", "https://abc.supabase.co/auth/v1",
                    "https://abc.supabase.co/x", "https://abc.supabase.co?a=1", "https://abc.supabase.co#x",
                    "https://", "http://[::1", "https://abc.supabase.co:99999", "http://localhost:0"):
            with self.subTest(url=url):
                self.assertIsNone(self._issuer(url))


class TestGetVerifier(unittest.TestCase):
    def setUp(self):
        get_verifier.cache_clear()
        self.addCleanup(get_verifier.cache_clear)

    def test_sin_supabase_url_no_hay_verificador(self):
        with patch.dict(os.environ):
            os.environ.pop("SUPABASE_URL", None)
            self.assertIsNone(get_verifier())

    def test_con_url_y_secreto_verifica_hs256_sin_tocar_la_red(self):
        entorno = {"SUPABASE_URL": PROYECTO, "SUPABASE_JWT_SECRET": f"  {SECRETO_HS256}  "}
        with patch.dict(os.environ, entorno):
            verificador = get_verifier()
        token = jwt.encode(claims_validos(), SECRETO_HS256, algorithm="HS256")
        self.assertEqual(verificador.verify(token).email, "ana@example.com")

    def test_el_verificador_se_crea_una_sola_vez(self):
        with patch.dict(os.environ, {"SUPABASE_URL": PROYECTO}):
            self.assertIs(get_verifier(), get_verifier())


class TestDependencias(unittest.TestCase):
    """get_current_user y require_admin sobre una mini-app, con claves y Supabase simulados."""

    def setUp(self):
        self.clave = nueva_clave_ec()
        self.servidor = SupabaseFalso(k1=self.clave)
        verificador = JwtVerifier(ISSUER, JwksCache(JWKS_URL, client=self.servidor.cliente, clock=RelojFalso()))
        patcher = patch("app.auth.get_verifier", return_value=verificador)
        patcher.start()
        self.addCleanup(patcher.stop)
        entorno = patch.dict(os.environ, {"AUTH_MODE": "required", "PROVIDER_MODE": "mock"})
        entorno.start()
        self.addCleanup(entorno.stop)
        self.client = TestClient(_app_de_prueba())

    def _get(self, ruta, token=None, **cabeceras):
        if token is not None:
            cabeceras["Authorization"] = f"Bearer {token}"
        return self.client.get(ruta, headers=cabeceras)

    def test_sin_cabecera_401_con_www_authenticate(self):
        r = self._get("/quien")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json(), {"detail": "No autenticado"})
        self.assertEqual(r.headers["www-authenticate"], "Bearer")

    def test_esquema_distinto_de_bearer_o_token_vacio(self):
        for cabecera in ("Basic YW5hOnB3", "Token abc", "Bearer", "Bearer ", "abc"):
            with self.subTest(cabecera=cabecera):
                self.assertEqual(self.client.get("/quien", headers={"Authorization": cabecera}).status_code, 401)

    def test_todos_los_rechazos_dicen_lo_mismo(self):
        # Un atacante no debe poder distinguir "expirado" de "firma mala" de "audiencia equivocada".
        rechazados = [
            firmar(self.clave, exp=int(time.time()) - 3600),
            firmar(nueva_clave_ec()),
            firmar(self.clave, aud="anon"),
            firmar(self.clave, kid="otro"),
            "basura",
        ]
        cuerpos = {self._get("/quien", t).text for t in rechazados}
        self.assertEqual(cuerpos, {'{"detail":"No autenticado"}'})

    def test_token_valido(self):
        r = self._get("/quien", firmar(self.clave))
        self.assertEqual((r.status_code, r.json()), (200, {"id": "11111111-2222-3333-4444-555555555555", "role": "usuario"}))

    def test_esquema_bearer_en_cualquier_capitalizacion(self):
        r = self.client.get("/quien", headers={"Authorization": f"bearer {firmar(self.clave)}"})
        self.assertEqual(r.status_code, 200)

    def test_ruta_de_admin(self):
        self.assertEqual(self._get("/solo-admin").status_code, 401)                      # sin sesión: 401, no 403
        self.assertEqual(self._get("/solo-admin", firmar(self.clave)).status_code, 403)  # usuario normal
        admin = firmar(self.clave, app_metadata={"role": "admin"})
        self.assertEqual(self._get("/solo-admin", admin).status_code, 200)

    def test_ser_admin_por_user_metadata_no_abre_la_ruta_de_admin(self):
        falso_admin = firmar(self.clave, user_metadata={"role": "admin"})
        self.assertEqual(self._get("/solo-admin", falso_admin).status_code, 403)

    def test_supabase_caido_es_503_generico(self):
        self.servidor.caido = True
        r = self._get("/quien", firmar(self.clave))
        self.assertEqual((r.status_code, r.json()), (503, {"detail": "Autenticación no disponible."}))

    def test_exigida_pero_sin_configurar_es_503_incluso_con_token(self):
        with patch("app.auth.get_verifier", return_value=None):
            self.assertEqual(self._get("/quien", firmar(self.clave)).status_code, 503)
            self.assertEqual(self._get("/quien").status_code, 503)

    def test_errata_en_auth_mode_no_apaga_la_proteccion(self):
        with patch.dict(os.environ, {"AUTH_MODE": "off"}):
            self.assertEqual(self._get("/quien").status_code, 401)

    def test_modo_disabled_con_mock_deja_pasar_al_usuario_de_desarrollo(self):
        with patch.dict(os.environ, {"AUTH_MODE": "disabled", "PROVIDER_MODE": "mock"}):
            r = self._get("/quien")
        self.assertEqual((r.status_code, r.json()["id"], r.json()["role"]), (200, "dev-local", "usuario"))

    def test_el_usuario_de_desarrollo_no_es_admin(self):
        with patch.dict(os.environ, {"AUTH_MODE": "disabled", "PROVIDER_MODE": "mock"}):
            self.assertEqual(self._get("/solo-admin").status_code, 403)

    def test_modo_disabled_no_se_permite_con_proveedores_reales(self):
        with patch.dict(os.environ, {"AUTH_MODE": "disabled", "PROVIDER_MODE": "real"}):
            r = self._get("/quien")
            self.assertEqual(r.status_code, 503)
            self.assertEqual(self._get("/quien", firmar(self.clave)).status_code, 503)  # ni siquiera con token


if __name__ == "__main__":
    unittest.main()
