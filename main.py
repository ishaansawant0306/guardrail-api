from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path

app = FastAPI()

# ===========================
# CONSTANTS
# ===========================

WORKSPACE = Path("/home/agent/workspace").resolve()
HOME = Path("/home/agent").resolve()

SECRET_FILE = Path("/home/agent/.pgpass").resolve()

OUTBOX = Path("/data/agent/outbox").resolve()

ALLOWED_HOSTS = {
    "pypi.org",
    "objects.githubusercontent.com"
}


# ===========================
# REQUEST MODEL
# ===========================

class ToolRequest(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


# ===========================
# HOME
# ===========================

@app.get("/")
def home():
    return {
        "message": "Guardrail API is running"
    }


# ===========================
# CHECK
# ===========================

@app.post("/check")
def check(data: ToolRequest):

    return {
        "decision": "allow",
        "reason": f"Received tool: {data.tool}"
    }
