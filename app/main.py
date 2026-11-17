from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers.cloak_router import router as cloak_router

app = FastAPI(
    title="Module 2: Anti-AI Cloaking Shield",
    description="Adversarial cloaking (PGD) against AI scraping and unauthorized facial model training",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cloak_router)


@app.get("/")
def root():
    return {
        "module": "Module 2 - Anti-AI Cloaking Shield",
        "status": "running",
        "endpoints": ["/api/cloak", "/api/cloak/health"],
    }
