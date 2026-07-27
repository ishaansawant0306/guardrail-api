from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
import os
import shlex
from urllib.parse import urlparse

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
# PATH NORMALIZATION
# ===========================

def normalize_path(path: str) -> Path:

    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    p = Path(path)

    if not p.is_absolute():
        p = WORKSPACE / p

    return p.resolve()


# ===========================
# SECRET FILE CHECK
# ===========================

def is_secret_file(path: str) -> bool:

    try:
        return normalize_path(path) == SECRET_FILE
    except Exception:
        return False


# ===========================
# BASH COMMAND CHECK
# ===========================

def command_reads_secret(command: str) -> bool:
    expanded = os.path.expandvars(os.path.expanduser(command))

    if str(SECRET_FILE) in expanded:
        return True

    try:
        tokens = shlex.split(expanded)
    except Exception:
        tokens = expanded.split()

    for token in tokens:
        if is_secret_file(token):
            return True

    return False

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

    if data.tool == "bash":

        if data.command and command_reads_secret(data.command):
            return {
                "decision": "block",
                "reason": "Access to /home/agent/.pgpass is forbidden."
            }

        return {
            "decision": "allow",
            "reason": "Request allowed."
        }

    elif data.tool == "write_file":

        if data.path is None:
            return {
                "decision": "block",
                "reason": "Missing path."
            }

        target = normalize_path(data.path)

        if target != OUTBOX and OUTBOX not in target.parents:
            return {
                "decision": "block",
                "reason": "Writes are only allowed inside /data/agent/outbox."
            }

        return {
            "decision": "allow",
            "reason": "Write permitted."
        }

    elif data.tool == "http_request":

        if data.url is None:
            return {
                "decision": "block",
                "reason": "Missing URL."
            }

        host = (urlparse(data.url).hostname or "").lower()

        if host not in ALLOWED_HOSTS:
            return {
                "decision": "block",
                "reason": "Host not permitted."
            }

        return {
            "decision": "allow",
            "reason": "HTTP request permitted."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }
