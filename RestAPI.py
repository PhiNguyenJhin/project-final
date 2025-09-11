from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy.orm import Session
import os

from cuối_kì import app, get_db, seed_data, ReportingService


class ChildActionIn(BaseModel):
    action: str
    payload: dict = {}


class ChildAPI:
    """
    Lớp 'con' cung cấp:
    - router: mount vào app để gọi từ bên ngoài (HTTP)
    - call_from_code(action, payload): gọi trực tiếp từ code (nội bộ)
    """
    router = APIRouter(prefix="/ext/child", tags=["ext-child"])

    @router.get("/health")
    def health():
        return {"ok": True, "msg": "Child API healthy"}

    @router.post("/run-action")
    def run_action(body: ChildActionIn = Body(...), db: Session = Depends(get_db)):
        return ChildAPI._dispatch_action(db, body.action, body.payload)

    @staticmethod
    def _dispatch_action(db: Session, action: str, payload: dict):
        """
        Dispatch các action tiện dụng. Hỗ trợ sẵn:
         - "seed": seed_data
         - "summary": ReportingService.program_summary
         - "custom_sql": chạy SQL thô
        """
        a = action.lower()
        if a == "seed":
            return seed_data.__wrapped__(db) if hasattr(seed_data, "__wrapped__") else seed_data(db=db)
        if a == "summary":
            rs = ReportingService(db).program_summary()
            return {"ok": True, "summary": rs}
        if a == "custom_sql":
            sql = payload.get("sql")
            if not sql:
                raise HTTPException(400, "Missing 'sql' in payload")
            try:
                res = db.execute(sql)
                rows = [dict(r) for r in res.mappings().all()]
                return {"ok": True, "rows": rows}
            except Exception as e:
                raise HTTPException(400, f"SQL error: {e}")
        raise HTTPException(400, f"Unknown action: {action}")

    @staticmethod
    def call_from_code(action: str, payload: dict = None):
        """Gọi trực tiếp từ code (nội bộ)."""
        db_gen = get_db()
        db = next(db_gen)
        try:
            return ChildAPI._dispatch_action(db, action, payload or {})
        finally:
            try:
                db_gen.close()
            except Exception:
                pass


app.include_router(ChildAPI.router)


def call_child_via_testclient(action: str, payload: dict = None):
    client = TestClient(app)
    resp = client.post("/ext/child/run-action", json={"action": action, "payload": payload or {}})
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    print(">>> ChildAPI internal test: summary")
    print(ChildAPI.call_from_code("summary"))
