from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import base64
from app.cloak import cloak_image

router = APIRouter(prefix="/api/cloak", tags=["cloak"])

class CloakRequest(BaseModel):
    image_base64: str
    epsilon: float = 8/255
    steps: int = 8

@router.get("/health")
def health():
    return {"status": "ok"}

@router.post("")
def cloak(req: CloakRequest):
    try:
        img_bytes = base64.b64decode(req.image_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64")
        
    try:
        cloaked_bytes, metrics = cloak_image(img_bytes, req.epsilon, req.steps)
        cloaked_b64 = base64.b64encode(cloaked_bytes).decode('utf-8')
        return {"cloaked_image_base64": cloaked_b64, "metrics": metrics, "status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
