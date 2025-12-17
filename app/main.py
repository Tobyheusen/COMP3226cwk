# FastAPI application entry point that initialises 
# the app and registers API routes.


from fastapi import FastAPI
from app.routes.auth import router as auth_router

app = FastAPI(title="QR Login Prototype")
app.include_router(auth_router)

@app.get("/health")
def health():
    return {"ok": True}
