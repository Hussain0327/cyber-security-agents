from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import time
from typing import Optional
import uuid

from .auth import verify_token
from .tracing import setup_tracing, trace_request
from ..core.graph import SecurityGraph
from ..core.models import SecurityProvider, AnalysisRequest, AnalysisResponse

logger = logging.getLogger(__name__)
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_tracing()
    logger.info("Security agents API starting up")
    yield
    logger.info("Security agents API shutting down")


app = FastAPI(
    title="Security Agents API",
    description="AI-powered cybersecurity analysis and response system",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    token = credentials.credentials
    user_id = await verify_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}


@app.post("/analyze", response_model=AnalysisResponse)
@trace_request
async def analyze_security_event(
    request: AnalysisRequest,
    user_id: str = Depends(get_current_user),
) -> AnalysisResponse:
    request_id = str(uuid.uuid4())
    logger.info(f"Processing analysis request {request_id} for user {user_id}")

    try:
        graph = SecurityGraph()
        result = await graph.analyze(request)

        return AnalysisResponse(
            request_id=request_id,
            analysis_type=request.analysis_type,
            findings=result.findings,
            recommendations=result.recommendations,
            confidence_score=result.confidence_score,
            threat_level=result.threat_level,
            mitre_techniques=result.mitre_techniques,
            sigma_rules=result.sigma_rules,
        )
    except Exception as e:
        logger.error(f"Analysis failed for request {request_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )


@app.get("/scenarios")
async def list_scenarios(user_id: str = Depends(get_current_user)):
    from ..scenarios import get_available_scenarios
    return {"scenarios": get_available_scenarios()}


@app.post("/scenarios/{scenario_name}/run")
async def run_scenario(
    scenario_name: str,
    user_id: str = Depends(get_current_user),
):
    from ..scenarios import run_scenario
    try:
        result = await run_scenario(scenario_name)
        return result
    except Exception as e:
        logger.error(f"Scenario {scenario_name} failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scenario execution failed: {str(e)}",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")