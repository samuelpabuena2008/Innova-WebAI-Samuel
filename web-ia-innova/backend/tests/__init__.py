"""Aislamiento de las pruebas: NUNCA deben usar una clave real ni tocar la red.

El código no lee el .env (lo hace uvicorn con --env-file), pero si alguien ejecuta las pruebas desde
una terminal que ya tiene GEMINI_API_KEY en el entorno, aquí se descarta y se fuerza el modo por reglas.
Se ejecuta antes de importar cualquier módulo de la app.
"""
import os

os.environ["GESTORA_MODE"] = "rules"
os.environ.pop("GEMINI_API_KEY", None)

# Lo mismo con la autenticación: ninguna prueba debe depender de un Supabase real ni de un AUTH_MODE
# que tenga la terminal. Sin estas variables la autenticación queda en su valor seguro ("required").
for variable in ("AUTH_MODE", "SUPABASE_URL", "SUPABASE_JWT_SECRET"):
    os.environ.pop(variable, None)
