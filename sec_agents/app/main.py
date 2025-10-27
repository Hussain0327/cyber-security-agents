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
from ..core.swe_graph import SWEOrchestrator
from ..core.swe_models import SWERequest, SWEResponse
from ..core.memory import get_memory_store

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
    return {"scenarios": await get_available_scenarios()}


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


# SWE Multi-Agent Orchestrator Endpoints


@app.post("/swe/orchestrate", response_model=SWEResponse)
@trace_request
async def swe_orchestrate(
    request: SWERequest,
    user_id: str = Depends(get_current_user),
) -> SWEResponse:
    """
    Execute a software engineering task using the multi-agent orchestrator.

    This endpoint coordinates 5 specialized agents (Research, Developer, Debugger,
    Reviewer, Reporter) to complete end-to-end SWE workflows.
    """
    logger.info(f"SWE orchestration request from user {user_id}: {request.task[:100]}")

    try:
        orchestrator = SWEOrchestrator(
            provider_type=request.provider or "openai",
            model_name=request.model_name
        )
        result = await orchestrator.execute(request)
        return result
    except Exception as e:
        logger.error(f"SWE orchestration failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SWE orchestration failed: {str(e)}",
        )


@app.get("/swe/session/{session_id}")
async def get_swe_session(
    session_id: str,
    user_id: str = Depends(get_current_user),
):
    """Get session information and message history."""
    try:
        memory_store = get_memory_store()
        session_info = memory_store.get_session_info(session_id)
        messages = memory_store.get_messages(session_id, limit=50)

        return {
            "session_info": session_info,
            "messages": messages,
        }
    except Exception as e:
        logger.error(f"Failed to get session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session: {str(e)}",
        )


@app.post("/swe/session/{session_id}/continue")
async def continue_swe_session(
    session_id: str,
    request: SWERequest,
    user_id: str = Depends(get_current_user),
) -> SWEResponse:
    """
    Continue an existing SWE session with a new task.

    This maintains conversation context from previous interactions.
    """
    logger.info(f"Continuing SWE session {session_id} from user {user_id}")

    # Override session_id from request with the one from path
    request.session_id = session_id

    try:
        orchestrator = SWEOrchestrator(
            provider_type=request.provider or "openai",
            model_name=request.model_name
        )
        result = await orchestrator.execute(request)
        return result
    except Exception as e:
        logger.error(f"SWE session continuation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SWE session continuation failed: {str(e)}",
        )


@app.delete("/swe/session/{session_id}")
async def clear_swe_session(
    session_id: str,
    user_id: str = Depends(get_current_user),
):
    """Clear a session from memory."""
    try:
        memory_store = get_memory_store()
        cleared = memory_store.clear_session(session_id)

        if cleared:
            return {"status": "success", "message": f"Session {session_id} cleared"}
        else:
            return {"status": "not_found", "message": f"Session {session_id} not found"}
    except Exception as e:
        logger.error(f"Failed to clear session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear session: {str(e)}",
        )


@app.get("/swe/sessions")
async def list_swe_sessions(
    user_id: str = Depends(get_current_user),
):
    """List all active SWE sessions."""
    try:
        memory_store = get_memory_store()
        sessions = memory_store.list_sessions()

        return {
            "sessions": sessions,
            "count": len(sessions),
        }
    except Exception as e:
        logger.error(f"Failed to list sessions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list sessions: {str(e)}",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")