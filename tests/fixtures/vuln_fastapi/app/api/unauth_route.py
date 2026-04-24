"""Fixture: FastAPI router with a route missing every auth dep.

The sast probe must flag this when config lists any `auth_dependencies`.
"""
from fastapi import APIRouter, Depends

router = APIRouter()


def get_current_user():  # placeholder — does nothing
    return None


@router.get("/public/ping")
async def public_ping():
    """Intentionally missing auth dep — sast probe should flag."""
    return {"ok": True}


@router.get("/authed/ping")
async def authed_ping(user=Depends(get_current_user)):
    """Has auth dep; should NOT be flagged."""
    return {"ok": True, "user": user}
