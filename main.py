from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Guardrail API is running"}

@app.post("/check")
async def check(request: Request):
    data = await request.json()

    return {
        "decision": "allow",
        "reason": f"Received tool: {data.get('tool')}"
    }
