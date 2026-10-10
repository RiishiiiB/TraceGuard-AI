from collections import OrderedDict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from . import scoring
from .analyzer import LogValidationError, analyze_csv, build_report
from .config import CONFIG
from .detector import rule_catalog
from .sample_data import demo_csv
from .schemas import AnalysisResult, RulesResponse

app = FastAPI(title="TraceGuard AI", version="1.0.0",
              description="Explainable authentication-log incident investigator (academic prototype).")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"], allow_headers=["*"],
)

# In-memory store of recent analyses (no database in the MVP).
_STORE: "OrderedDict[str, AnalysisResult]" = OrderedDict()
_STORE_LIMIT = 20


def _save(result: AnalysisResult) -> AnalysisResult:
    _STORE[result.analysis_id] = result
    while len(_STORE) > _STORE_LIMIT:
        _STORE.popitem(last=False)
    return result


def _get(analysis_id: str) -> AnalysisResult:
    if analysis_id not in _STORE:
        raise HTTPException(404, detail={"message": "Analysis not found. It may have expired; run the analysis again."})
    return _STORE[analysis_id]


@app.exception_handler(LogValidationError)
async def _validation_handler(_, exc: LogValidationError):
    return JSONResponse(status_code=exc.status, content={"detail": {"message": exc.message, "details": exc.details}})


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "traceguard-ai", "version": app.version}


@app.get("/api/demo-data")
def demo_data():
    """Download the synthetic sample CSV."""
    return Response(demo_csv(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="traceguard_sample_auth_log.csv"'})


@app.post("/api/analyze/demo", response_model=AnalysisResult)
def analyze_demo():
    return _save(analyze_csv(demo_csv().encode(), "traceguard_sample_auth_log.csv (synthetic)", is_demo=True))


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_upload(file: UploadFile = File(...)):
    data = await file.read(CONFIG.max_upload_bytes + 1)
    name = (file.filename or "upload.csv").replace("\\", "/").split("/")[-1][:120]
    return _save(analyze_csv(data, name, is_demo=False))


@app.get("/api/rules", response_model=RulesResponse)
def rules():
    return RulesResponse(
        rules=rule_catalog(CONFIG),
        scoring_model=scoring.SCORING_MODEL,
        correlation_model={
            "description": "Findings are linked into one incident when they share a source IP or a username "
                           f"and their time ranges are within {CONFIG.incident_gap_min} minutes of each other. "
                           "Links are transitive.",
            "gap_minutes": CONFIG.incident_gap_min,
        },
        limitations=[
            "Rules are deterministic thresholds; there is no machine learning or LLM involved.",
            "IP geolocation, threat-intelligence lookups and attribution are NOT implemented.",
            "Timestamps without a timezone are interpreted as UTC; unusual hours are evaluated in UTC.",
            "Shared NAT/proxy addresses and service accounts can cause false positives.",
        ],
    )


@app.get("/api/analysis/{analysis_id}", response_model=AnalysisResult)
def get_analysis(analysis_id: str):
    return _get(analysis_id)


@app.get("/api/analysis/{analysis_id}/report")
def get_report(analysis_id: str):
    report = build_report(_get(analysis_id))
    return JSONResponse(report, headers={
        "Content-Disposition": f'attachment; filename="traceguard_report_{analysis_id}.json"'})
