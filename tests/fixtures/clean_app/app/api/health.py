"""Clean fixture — every route has an auth dep."""
from fastapi import APIRouter, Depends

router = APIRouter()


def get_current_user():
    return None


@router.get("/healthz")
async def healthz(user=Depends(get_current_user)):
    return {"ok": True}
