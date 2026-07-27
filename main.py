from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Guardrail API is running"}

@app.post("/check")
def check():
    return {
        "decision": "allow",
        "reason": "Test endpoint working"
    }
