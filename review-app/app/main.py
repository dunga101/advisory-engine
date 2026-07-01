from fastapi import FastAPI

app = FastAPI(title="advisory-engine review-app")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
