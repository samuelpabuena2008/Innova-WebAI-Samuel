import logging
import os
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.auth import AuthUser, get_current_user
from app.providers import ProviderError, get_provider, modo_real
from app.gestora import get_classifier, gestora_status
from app.router import PRIVATE_CATEGORY, decide, fallback_models
from app.schemas import MeResponse, OrchestrateRequest, OrchestrateResponse

# Este código NO lee el archivo .env. En local se carga al arrancar con `uvicorn ... --env-file .env`;
# en producción las variables vienen del hosting (Secrets). Así no hay forma de cargar un .env por accidente.

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("orchestrator")

app = FastAPI(title="IA Gestora / Orquestadora — Web IA INNOVA", version="0.1.0")

origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["POST", "GET"], allow_headers=["Content-Type", "Authorization"])


def _ruta_privada_valida() -> bool:
    """PRIVATE_ROUTE_URL debe existir (sin contar espacios) y ser https://.

    PENDIENTE (P-02): todavía no existe un proveedor privado que USE esta URL; mientras tanto
    es solo una compuerta de seguridad. Bloquea PROVIDER_MODE=real hasta decidir dónde corre la ruta privada.
    """
    return os.getenv("PRIVATE_ROUTE_URL", "").strip().lower().startswith("https://")


@app.get("/health")
def health():
    # gestora_status() informa el modo efectivo y SI hay clave (true/false), nunca la clave.
    return {"status": "ok", "provider_mode": os.getenv("PROVIDER_MODE", "mock"), **gestora_status()}


@app.get("/me", response_model=MeResponse)
def me(user: AuthUser = Depends(get_current_user)):
    """Quién es el usuario del token y qué rol tiene. El frontend lo usa para saber si mostrar lo de admin."""
    return MeResponse(id=user.id, email=user.email, role=user.role)


# MVP-1: /orchestrate exige sesión. `Depends(get_current_user)` corre ANTES del cuerpo de la función:
# sin un JWT válido de Supabase responde 401 y no se clasifica ni se llama a ningún proveedor.
@app.post("/orchestrate", response_model=OrchestrateResponse)
def orchestrate(req: OrchestrateRequest, user: AuthUser = Depends(get_current_user)):
    start = time.perf_counter()
    request_id = str(uuid.uuid4())
    provider = get_provider()
    is_mock = not modo_real()

    decision = decide(req.message, get_classifier())
    model, reason, fallback_used = decision.model, decision.reason, False

    # P-02, fallo cerrado: en modo real, lo privado solo va a una ruta privada CONFIGURADA
    # (PRIVATE_ROUTE_URL). Sin ella NO se llama a ningún proveedor, para no enviar texto
    # sensible a un tercero por accidente. En modo mock no hace falta (no sale nada).
    if decision.category == PRIVATE_CATEGORY and not is_mock and not _ruta_privada_valida():
        log.warning("req=%s category=%s ruta privada no configurada: 503", request_id, decision.category)
        raise HTTPException(status_code=503, detail="Ruta privada no disponible todavía")

    try:
        content = provider.generate(model, req.message)
    except ProviderError as exc:
        # Solo el tipo de error: el texto de la excepción podría incluir contenido del usuario.
        log.warning("Falló %s (%s). Probando respaldo.", model, type(exc).__name__)
        content = None
        for backup in fallback_models(decision.category, model):
            try:
                content = provider.generate(backup, req.message)
                model, fallback_used = backup, True
                reason = f"{reason} (respaldo: falló el modelo principal)"
                break
            except ProviderError as backup_exc:
                log.warning("Respaldo %s también falló (%s).", backup, type(backup_exc).__name__)
                continue
        if content is None:
            # Error normalizado sin exponer detalles internos.
            raise HTTPException(status_code=502, detail="Ningún proveedor disponible en este momento.")

    latency_ms = int((time.perf_counter() - start) * 1000)
    # Registro de la decisión (el contenido del usuario NO se guarda en logs). `user` es el UUID de Supabase,
    # no el correo: permite saber quién consumió qué (RNF-04, cuotas por usuario) sin guardar datos personales.
    log.info("req=%s user=%s category=%s decided_by=%s model=%s fallback=%s latency_ms=%s",
             request_id, user.id, decision.category, decision.decided_by, model, fallback_used, latency_ms)

    return OrchestrateResponse(
        request_id=request_id, content=content, model=model, category=decision.category,
        reason=reason, latency_ms=latency_ms, fallback_used=fallback_used, is_mock=is_mock,
        decided_by=decision.decided_by,
    )
