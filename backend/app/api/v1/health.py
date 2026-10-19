from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.health import check_db, check_redis

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/ready")
def ready(db: Session = Depends(get_db)) -> JSONResponse:
    db_h = check_db(db)
    redis_h = check_redis()
    ok = db_h["ok"] and redis_h["ok"]
    return JSONResponse({"status": "ready" if ok else "not_ready", "database": db_h["ok"], "redis": redis_h["ok"]},
                        status_code=200 if ok else 503)
