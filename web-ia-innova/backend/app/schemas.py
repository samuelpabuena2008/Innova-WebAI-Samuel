from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# Límite del mensaje. Debe ser mayor que LONG_CONTEXT_CHARS (8000) del router,
# o la regla 40 por longitud nunca se activaría. El frontend usa el mismo valor
# (constante en orchestratorApi.ts).
MAX_MESSAGE_CHARS = 32_000


class OrchestrateRequest(BaseModel):
    # str_strip_whitespace: recorta espacios; así "   " queda vacío y min_length lo rechaza.
    model_config = ConfigDict(str_strip_whitespace=True)

    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class MeResponse(BaseModel):
    """Respuesta de GET /me: la identidad que el backend extrajo del token (nunca algo que mande el cliente)."""

    id: str
    email: Optional[str] = None
    role: Literal["usuario", "admin"]


class OrchestrateResponse(BaseModel):
    request_id: str
    content: str
    model: str
    category: str
    reason: str
    latency_ms: int
    fallback_used: bool = False
    is_mock: bool = False
    # Quién decidió la ruta: reglas, IA Gestora (Gemini clasificó) o reglas porque Gemini falló.
    decided_by: Literal["regla", "gestora_llm", "regla_respaldo"] = "regla"
