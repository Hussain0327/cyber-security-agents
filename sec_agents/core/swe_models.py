from enum import Enum
from typing import Dict, List, Optional, Any, TypedDict, Annotated
from pydantic import BaseModel, Field
from langchain_core.messages import BaseMessage


class AgentRole(str, Enum):
    """Available specialized agent roles in the SWE orchestrator."""
    RESEARCH = "research"
    DEVELOPER = "developer"
    DEBUGGER = "debugger"
    REVIEWER = "reviewer"
    REPORTER = "reporter"


class TaskComplexity(str, Enum):
    """Estimated complexity level of the SWE task."""
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"


class SWERequest(BaseModel):
    """Request model for SWE orchestrator tasks."""
    task: str = Field(..., description="The software engineering task to execute")
    session_id: Optional[str] = Field(default="default-session", description="Session ID for conversation continuity")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context for the task")
    max_iterations: Optional[int] = Field(default=50, description="Maximum orchestrator iterations")
    provider: Optional[str] = Field(default="openai", description="LLM provider (openai, anthropic)")
    model_name: Optional[str] = Field(default=None, description="Specific model to use")


class AgentInvocation(BaseModel):
    """Record of a specialized agent being invoked."""
    agent_role: AgentRole
    input: str
    output: str
    timestamp: float
    tokens_used: Optional[int] = None


class ResearchFinding(BaseModel):
    """A research finding from the Research Agent."""
    topic: str
    key_findings: List[str]
    sources: List[str]
    code_examples: Optional[str] = None
    caveats: List[str] = []
    confidence_level: str = Field(default="medium", pattern="^(high|medium|low)$")


class CodeImplementation(BaseModel):
    """Code implementation from the Developer Agent."""
    feature_name: str
    design_decisions: List[str]
    code: str
    language: str
    usage_example: Optional[str] = None
    dependencies: List[str] = []
    testing_considerations: List[str] = []


class DebugReport(BaseModel):
    """Debug report from the Debugger Agent."""
    component: str
    issues_found: List[Dict[str, str]]  # {title, location, problem, impact}
    root_cause: Optional[str] = None
    proposed_fix: Optional[str] = None
    test_cases: List[str] = []
    validation_steps: List[str] = []


class ReviewReport(BaseModel):
    """Review report from the Reviewer Agent."""
    component: str
    assessment: str = Field(pattern="^(approved|needs_revision|rejected)$")
    correctness_review: Dict[str, List[str]]  # {correct: [...], needs_fixing: [...]}
    security_review: Dict[str, List[str]]  # {measures: [...], concerns: [...]}
    fact_check_results: List[Dict[str, str]]  # {claim, status, source}
    required_changes: List[str] = []
    recommendations: List[str] = []


class TechnicalReport(BaseModel):
    """Final technical report from the Reporter Agent."""
    title: str
    executive_summary: str
    task_breakdown: List[str]
    research_findings: List[ResearchFinding] = []
    implementations: List[CodeImplementation] = []
    debug_reports: List[DebugReport] = []
    review_reports: List[ReviewReport] = []
    final_deliverables: List[str]
    verification_steps: List[str]
    next_steps: List[str]
    references: List[str] = []


class SWEResponse(BaseModel):
    """Response model from the SWE orchestrator."""
    request_id: str
    session_id: str
    task: str
    status: str = Field(pattern="^(completed|failed|partial)$")
    complexity: Optional[TaskComplexity] = None
    report: str = Field(..., description="Final technical report in markdown format")
    structured_report: Optional[TechnicalReport] = Field(default=None, description="Structured report data")
    agent_invocations: List[AgentInvocation] = Field(default_factory=list)
    iterations_used: int = Field(default=0)
    total_tokens: Optional[int] = None
    execution_time_seconds: Optional[float] = None
    timestamp: str


class SWEAgentState(TypedDict):
    """State object passed between nodes in the SWE orchestrator graph."""
    messages: Annotated[List[BaseMessage], "Conversation messages"]
    request: SWERequest
    task_breakdown: List[str]
    research_findings: List[ResearchFinding]
    code_implementations: List[CodeImplementation]
    debug_reports: List[DebugReport]
    review_reports: List[ReviewReport]
    technical_report: Optional[TechnicalReport]
    final_output: str
    iterations: int
    agent_invocations: List[AgentInvocation]
    provider: Any  # SecurityProvider instance
    session_data: Dict[str, Any]  # Session-specific data


class SessionMemory(BaseModel):
    """Session memory for conversation continuity."""
    session_id: str
    messages: List[Dict[str, str]] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    message_count: int = 0
    max_messages: int = 20  # Window size like n8n
