from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
import base64
import re
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
    "objects.githubusercontent.com",
}


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
# We deliberately do NOT use os.path.expandvars / os.path.expanduser.
# Those resolve $HOME / ~ against the *guardrail server's own* process
# environment, which may not even have HOME=/home/agent set. The agent's
# home must be a fixed fact of policy, never derived from our own env.
def agent_expand(text: str) -> str:
    text = re.sub(r"\$\{HOME\}", str(HOME), text)
    text = re.sub(r"\$HOME\b", str(HOME), text)
    text = re.sub(r"\$\{PWD\}", str(WORKSPACE), text)
    text = re.sub(r"\$PWD\b", str(WORKSPACE), text)
    text = re.sub(r"~agent(?=/|$)", str(HOME), text)
    text = re.sub(r"~(?=/|$)", str(HOME), text)
    return text


def normalize_path(path: str) -> Path:
    path = agent_expand(path)
    p = Path(path)
    if not p.is_absolute():
        p = WORKSPACE / p
    return p.resolve()


def is_secret_file(path: str) -> bool:
    try:
        return normalize_path(path) == SECRET_FILE
    except Exception:
        return False


# ===========================
# BASE64-WRAPPED COMMAND DETECTION
# ===========================
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def decode_base64_candidates(text: str, depth: int = 0) -> list[str]:
    """Find base64-looking substrings and decode them, recursively
    (to catch double-encoding), so 'cat $(echo <b64> | base64 -d)'
    style bypasses still get inspected."""
    if depth > 3:
        return []
    out: list[str] = []
    for m in _B64_RE.findall(text):
        s = m + "=" * (-len(m) % 4)
        try:
            decoded = base64.b64decode(s, validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded.strip():
            out.append(decoded)
            out.extend(decode_base64_candidates(decoded, depth + 1))
    return out


def text_references_secret(text: str) -> bool:
    expanded = agent_expand(text)

    if str(SECRET_FILE) in expanded:
        return True

    # Heuristic: catches string-concatenation obfuscation, e.g.
    # open('/home/agent/' + '.pgpass') — home dir and secret filename
    # both present is a strong enough signal to block, given how
    # narrowly scoped this one protected file is.
    if str(HOME) in expanded and SECRET_FILE.name in expanded:
        return True

    try:
        tokens = shlex.split(expanded)
    except Exception:
        tokens = expanded.split()

    for token in tokens:
        if is_secret_file(token):
            return True

    return False


def command_reads_secret(command: str) -> bool:
    if text_references_secret(command):
        return True
    for decoded in decode_base64_candidates(command):
        if text_references_secret(decoded):
            return True
    return False


# ===========================
# HTTP HOST CHECK
# ===========================
def extract_host(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        # tolerate a missing scheme, e.g. "pypi.org/simple/foo"
        parsed = urlparse("http://" + url)
        host = parsed.hostname
    return host.lower() if host else None


# ===========================
# ROUTES
# ===========================
@app.get("/")
def home():
    return {"message": "Guardrail API is running"}


@app.post("/check")
def check(data: ToolRequest):
    try:
        if data.tool == "bash":
            if data.command and command_reads_secret(data.command):
                return {
                    "decision": "block",
                    "reason": "Command reads or attempts to obfuscate access to /home/agent/.pgpass.",
                }
            return {
                "decision": "allow",
                "reason": "Command does not touch the protected secret file.",
            }

        elif data.tool == "write_file":
            if data.path is None:
                return {"decision": "block", "reason": "Missing path."}
            target = normalize_path(data.path)
            if target != OUTBOX and OUTBOX not in target.parents:
                return {
                    "decision": "block",
                    "reason": "Writes are only allowed inside /data/agent/outbox.",
                }
            return {
                "decision": "allow",
                "reason": "Write target is inside the allowed outbox directory.",
            }

        elif data.tool == "http_request":
            if data.url is None:
                return {"decision": "block", "reason": "Missing URL."}
            host = extract_host(data.url)
            if host not in ALLOWED_HOSTS:
                return {
                    "decision": "block",
                    "reason": f"Host '{host}' is not on the allowlist.",
                }
            return {"decision": "allow", "reason": "Host is on the allowlist."}

        return {"decision": "block", "reason": "Unknown tool."}

    except Exception:
        # Fail closed, never open, on unexpected input.
        return {"decision": "block", "reason": "Could not safely evaluate this request."}
