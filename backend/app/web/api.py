import threading
from collections import deque
import time
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db import WebAssessment, session
from app.schemas import StrictModel
from app.web.transport import TargetError, fetch_page, normalize_url
from app.web.checks import inspect

router = APIRouter(prefix="/api/web", tags=["Website assessments"])
slots = threading.BoundedSemaphore(2)
recent = deque()
lock = threading.Lock()


class AssessmentRequest(StrictModel):
    url: str = Field(min_length=8, max_length=2000)
    authorized: Literal[True]


def rate_limit():
    with lock:
        now = time.monotonic()
        while recent and recent[0] < now - 60:
            recent.popleft()
        if len(recent) >= 10:
            raise HTTPException(
                429, "Assessment limit reached. Wait a minute before retrying.", headers={"Retry-After": "60"}
            )
        recent.append(now)


@router.post("/assessments", status_code=201)
def assess(body: AssessmentRequest, db: Session = Depends(session)):
    try:
        normalize_url(body.url)
    except TargetError as error:
        raise HTTPException(422, str(error)) from error
    rate_limit()
    if not slots.acquire(blocking=False):
        raise HTTPException(429, "Two assessments are already running; retry shortly.")
    try:
        try:
            report = inspect(fetch_page(body.url))
        except TargetError as error:
            raise HTTPException(422, str(error)) from error
        key = str(uuid4())
        report["id"] = key
        record = WebAssessment(id=key, url=report["url"], report=report)
        db.add(record)
        db.commit()
        return report
    finally:
        slots.release()


@router.get("/assessments")
def history(db: Session = Depends(session)):
    return [
        {"id": r.id, "url": r.url, "created_at": r.report["created_at"], "summary": r.report["summary"]}
        for r in db.scalars(select(WebAssessment).order_by(WebAssessment.created_at.desc()).limit(20))
    ]


@router.get("/assessments/{assessment_id}")
def get_report(assessment_id: str, db: Session = Depends(session)):
    record = db.get(WebAssessment, assessment_id)
    if record is None:
        raise HTTPException(404, "Assessment not found")
    return record.report
