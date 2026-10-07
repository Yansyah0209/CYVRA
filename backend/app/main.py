import json
import logging
import os
from pathlib import Path
from uuid import uuid4
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db import Project, session
from app.schemas import ProjectCreate, Dataset, SimulationRequest, OptimizeRequest, Question
from app.intelligence.risk import analyze
from app.intelligence.counterfactual import simulate, recommend
from app.ai.explainer import GroundedExplainer
from app.web.api import router as web_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
app = FastAPI(
    title="CYVRA",
    version="0.2.0",
    description="Defensive evidence-aware cyber risk intelligence. Local single-user research MVP.",
)
app.include_router(web_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def guard(request: Request, call_next):
    from starlette.responses import JSONResponse

    key = os.getenv("CYVRA_API_KEY", "")
    if key and request.url.path.startswith("/api/"):
        import secrets

        if not secrets.compare_digest(request.headers.get("x-api-key", ""), key):
            return JSONResponse({"detail": "Invalid API key"}, status_code=401)
    if request.method == "POST":
        # Count streamed bytes, rather than trusting Content-Length.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_000_000:
                return JSONResponse({"detail": "Request exceeds 2 MB"}, status_code=413)
        request._body = bytes(body)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.get("/api/projects")
def list_projects(db: Session = Depends(session)):
    return [
        {"id": p.id, "name": p.name, "has_data": p.dataset is not None}
        for p in db.scalars(select(Project).order_by(Project.created_at))
    ]


@app.post("/api/projects", status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(session)):
    p = Project(id=str(uuid4()), name=body.name)
    db.add(p)
    db.commit()
    return {"id": p.id, "name": p.name}


def project(project_id: str, db: Session) -> Project:
    p = db.get(Project, project_id)
    if p is None:
        raise HTTPException(404, "Project not found")
    return p


def dataset(project_id: str, db: Session) -> Dataset:
    p = project(project_id, db)
    if p.dataset is None:
        raise HTTPException(409, "Import a dataset first")
    return Dataset.model_validate(p.dataset)


@app.post("/api/projects/{project_id}/import")
def import_data(project_id: str, body: Dataset, db: Session = Depends(session)):
    p = project(project_id, db)
    p.dataset = body.model_dump(mode="json")
    db.commit()
    logging.info("dataset_import project=%s assets=%d findings=%d", p.id, len(body.assets), len(body.findings))
    return {"assets": len(body.assets), "findings": len(body.findings), "relationships": len(body.relationships)}


@app.post("/api/projects/{project_id}/demo")
def demo(project_id: str, db: Session = Depends(session)):
    app_root = Path(__file__).resolve().parents[1]
    configured = os.getenv("DEMO_DATA_PATH")
    candidates = (
        [Path(configured)]
        if configured
        else [
            app_root / "datasets/synthetic/aurora.json",
            app_root.parent / "datasets/synthetic/aurora.json",
        ]
    )
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        raise HTTPException(503, "Demo dataset unavailable; check DEMO_DATA_PATH")
    return import_data(project_id, Dataset.model_validate(json.loads(path.read_text())), db)


@app.get("/api/projects/{project_id}/dataset")
def export(project_id: str, db: Session = Depends(session)):
    return dataset(project_id, db)


@app.get("/api/projects/{project_id}/analysis")
def analysis(project_id: str, db: Session = Depends(session)):
    return analyze(dataset(project_id, db))


@app.post("/api/projects/{project_id}/simulate")
def simulation(project_id: str, body: SimulationRequest, db: Session = Depends(session)):
    try:
        return simulate(dataset(project_id, db), body.actions)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error


@app.post("/api/projects/{project_id}/recommendations")
def recommendations(project_id: str, body: OptimizeRequest, db: Session = Depends(session)):
    return recommend(dataset(project_id, db), body.budget)


@app.post("/api/projects/{project_id}/explain")
def explain(project_id: str, body: Question, db: Session = Depends(session)):
    data = dataset(project_id, db)
    return GroundedExplainer().explain(body.question, analyze(data), recommend(data))
