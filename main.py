from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class ToolRequest(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


@app.get("/")
def home():
    return {
        "message": "Guardrail API is running"
    }


@app.post("/check")
def check(data: ToolRequest):
    return {
        "decision": "allow",
        "reason": f"Received tool: {data.tool}"
    }
