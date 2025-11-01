import time
import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from langgraph.graph import StateGraph, END

from .swe_models import (
    SWERequest,
    SWEResponse,
    SWEAgentState,
    AgentInvocation,
    AgentRole,
    TaskComplexity,
)
from .swe_agents import get_agent
from .memory import get_memory_store
from .models import get_provider
from ..tools.code_executor import get_executor

logger = logging.getLogger(__name__)


class SWEOrchestrator:

    def __init__(self, provider_type: str = "openai", model_name: str = None):
        """
        Initialize SWE orchestrator.

        Args:
            provider_type: LLM provider (openai, anthropic, local)
            model_name: Specific model to use (optional)
        """
        self.provider_type = provider_type
        self.model_name = model_name
        self.provider = get_provider(provider_type, model_name)
        self.memory_store = get_memory_store()
        self.code_executor = get_executor()

        # Initialize specialized agents
        self.research_agent = get_agent("research", self.provider)
        self.developer_agent = get_agent("developer", self.provider)
        self.debugger_agent = get_agent("debugger", self.provider)
        self.reviewer_agent = get_agent("reviewer", self.provider)
        self.reporter_agent = get_agent("reporter", self.provider)

        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow."""
        workflow = StateGraph(SWEAgentState)

        # Add nodes
        workflow.add_node("initialize", self._initialize_node)
        workflow.add_node("plan_task", self._plan_task_node)
        workflow.add_node("research", self._research_node)
        workflow.add_node("develop", self._develop_node)
        workflow.add_node("debug", self._debug_node)
        workflow.add_node("review", self._review_node)
        workflow.add_node("report", self._report_node)
        workflow.add_node("finalize", self._finalize_node)

        # Set entry point
        workflow.set_entry_point("initialize")

        # Add edges (workflow path)
        workflow.add_edge("initialize", "plan_task")
        workflow.add_edge("plan_task", "research")
        workflow.add_edge("research", "develop")
        workflow.add_edge("develop", "debug")
        workflow.add_edge("debug", "review")
        workflow.add_edge("review", "report")
        workflow.add_edge("report", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile()

    async def execute(self, request: SWERequest) -> SWEResponse:
        start_time = time.time()
        request_id = str(uuid.uuid4())

        logger.info(
            f"Starting SWE task {request_id}: {request.task[:100]}..."
        )

        # Load session memory
        session_messages = self.memory_store.get_messages(
            request.session_id,
            limit=request.max_iterations
        )

        # Initialize state
        initial_state = SWEAgentState(
            messages=[
                SystemMessage(content=self._get_planner_system_prompt()),
                HumanMessage(content=f"Task: {request.task}")
            ] + [
                HumanMessage(content=msg["content"])
                if msg["role"] == "user"
                else AIMessage(content=msg["content"])
                for msg in session_messages
            ],
            request=request,
            task_breakdown=[],
            research_findings=[],
            code_implementations=[],
            debug_reports=[],
            review_reports=[],
            technical_report=None,
            final_output="",
            iterations=0,
            agent_invocations=[],
            provider=self.provider,
            session_data={},
        )

        try:
            # Run the graph
            final_state = await self.graph.ainvoke(initial_state)

            # Save to session memory
            self.memory_store.add_message(
                request.session_id,
                "user",
                request.task
            )
            self.memory_store.add_message(
                request.session_id,
                "assistant",
                final_state["final_output"]
            )

            execution_time = time.time() - start_time

            # Build response
            response = SWEResponse(
                request_id=request_id,
                session_id=request.session_id,
                task=request.task,
                status="completed",
                report=final_state["final_output"],
                structured_report=final_state.get("technical_report"),
                agent_invocations=final_state["agent_invocations"],
                iterations_used=final_state["iterations"],
                execution_time_seconds=execution_time,
                timestamp=datetime.now().isoformat(),
            )

            logger.info(
                f"SWE task {request_id} completed in {execution_time:.2f}s"
            )

            return response

        except Exception as e:
            logger.error(f"SWE task {request_id} failed: {str(e)}", exc_info=True)

            execution_time = time.time() - start_time

            # Return error response
            return SWEResponse(
                request_id=request_id,
                session_id=request.session_id,
                task=request.task,
                status="failed",
                report=f"# Task Failed\n\nError: {str(e)}",
                agent_invocations=[],
                iterations_used=0,
                execution_time_seconds=execution_time,
                timestamp=datetime.now().isoformat(),
            )

    def _get_planner_system_prompt(self) -> str:
        return """You are the Orchestrator of a multi-agent software engineering system. Your mission is to coordinate specialized AI agents to complete end-to-end SWE workflows with precision and reliability.

# Available Specialized Agents:

1. **Research Agent** - Gathers verified technical information, documentation, and flags uncertain claims. Use for: API research, library documentation, best practices lookup.

2. **Developer Agent** - Writes production-ready code following clean architecture principles. Use for: Implementation, code generation, refactoring.

3. **Debugger Agent** - Reviews outputs, finds issues, proposes fixes, validates corrections. Use for: Testing, error analysis, validation.

4. **Reviewer Agent** - Fact-checks outputs, validates assumptions, enforces standards. Use for: Quality assurance, security review, correctness validation.

5. **Reporter Agent** - Compiles results into structured technical reports. Use for: Final documentation, summary generation.

# Your Responsibilities:
- Break down the task into logical steps
- Delegate to appropriate specialized agents
- Ensure all claims are verified before proceeding
- Coordinate debugging before final reporting
- Maintain conversation context across iterations

# Collaboration Rules:
- All claims must be supported by code execution, documentation, or verified sources
- If uncertainty detected, escalate to Research Agent
- Debugging occurs BEFORE final reporting
- Each agent provides structured outputs (Markdown/JSON)

Prioritize: correctness → clarity → usefulness → speed"""

    async def _initialize_node(self, state: SWEAgentState) -> SWEAgentState:
        """Initialize the workflow."""
        logger.info("Initializing SWE workflow")
        state["iterations"] += 1
        state["messages"].append(
            AIMessage(content="Workflow initialized. Starting task analysis...")
        )
        return state

    async def _plan_task_node(self, state: SWEAgentState) -> SWEAgentState:
        """Plan and break down the task."""
        logger.info("Planning task breakdown")

        request = state["request"]

        # Simple task breakdown (in production, could use LLM for this)
        state["task_breakdown"] = [
            "Research technical requirements and best practices",
            "Develop implementation following clean architecture",
            "Test and debug the implementation",
            "Review for quality, security, and correctness",
            "Generate comprehensive technical report",
        ]

        state["messages"].append(
            AIMessage(
                content=f"Task breakdown complete: {len(state['task_breakdown'])} steps"
            )
        )

        return state

    async def _research_node(self, state: SWEAgentState) -> SWEAgentState:
        """Execute research phase."""
        logger.info("Executing research agent")

        invocation_start = time.time()

        # Prepare research prompt
        research_prompt = f"""Research the following software engineering task and provide verified information:

Task: {state['request'].task}

Please research:
1. Relevant libraries, frameworks, or tools
2. Best practices and design patterns
3. Code examples from official documentation
4. Any security considerations or known issues
5. Version compatibility notes

Provide structured findings with sources."""

        # Execute research agent
        output = await self.research_agent.execute(research_prompt, {})

        # Record invocation
        state["agent_invocations"].append(
            AgentInvocation(
                agent_role=AgentRole.RESEARCH,
                input=research_prompt[:200] + "...",
                output=output,
                timestamp=invocation_start,
            )
        )

        state["messages"].append(
            AIMessage(content=f"Research complete: {len(output)} chars of findings")
        )

        # Store research findings (simplified)
        state["session_data"]["research_output"] = output

        return state

    async def _develop_node(self, state: SWEAgentState) -> SWEAgentState:
        """Execute development phase."""
        logger.info("Executing developer agent")

        invocation_start = time.time()

        # Prepare development prompt
        research_output = state["session_data"].get("research_output", "")

        dev_prompt = f"""Based on the research findings, implement the following task:

Task: {state['request'].task}

Research Findings:
{research_output[:1000]}...

Please provide:
1. Clean, production-ready code
2. Design decisions and architecture
3. Usage examples
4. Testing considerations
5. Required dependencies

Follow best practices and include comprehensive documentation."""

        # Execute developer agent
        output = await self.developer_agent.execute(dev_prompt, {})

        # Record invocation
        state["agent_invocations"].append(
            AgentInvocation(
                agent_role=AgentRole.DEVELOPER,
                input=dev_prompt[:200] + "...",
                output=output,
                timestamp=invocation_start,
            )
        )

        state["messages"].append(
            AIMessage(content=f"Development complete: Code generated")
        )

        # Store code
        state["session_data"]["code_output"] = output

        return state

    async def _debug_node(self, state: SWEAgentState) -> SWEAgentState:
        """Execute debugging phase."""
        logger.info("Executing debugger agent")

        invocation_start = time.time()

        # Prepare debug prompt
        code_output = state["session_data"].get("code_output", "")

        debug_prompt = f"""Review and test the following implementation for issues:

Task: {state['request'].task}

Implementation:
{code_output[:1500]}...

Please:
1. Identify any bugs or issues
2. Check for edge cases
3. Validate error handling
4. Propose specific fixes
5. Suggest test cases

Provide a detailed debug report."""

        # Execute debugger agent
        output = await self.debugger_agent.execute(debug_prompt, {})

        # Record invocation
        state["agent_invocations"].append(
            AgentInvocation(
                agent_role=AgentRole.DEBUGGER,
                input=debug_prompt[:200] + "...",
                output=output,
                timestamp=invocation_start,
            )
        )

        state["messages"].append(
            AIMessage(content=f"Debugging complete: Issues analyzed")
        )

        # Store debug output
        state["session_data"]["debug_output"] = output

        return state

    async def _review_node(self, state: SWEAgentState) -> SWEAgentState:
        """Execute review phase."""
        logger.info("Executing reviewer agent")

        invocation_start = time.time()

        # Prepare review prompt
        code_output = state["session_data"].get("code_output", "")
        debug_output = state["session_data"].get("debug_output", "")

        review_prompt = f"""Perform quality assurance review on the following implementation:

Task: {state['request'].task}

Implementation:
{code_output[:1000]}...

Debug Report:
{debug_output[:1000]}...

Please review:
1. Correctness and accuracy
2. Security considerations
3. Code quality and standards
4. Completeness
5. Fact-check technical claims

Provide assessment: APPROVED, NEEDS REVISION, or REJECTED with detailed justification."""

        # Execute reviewer agent
        output = await self.reviewer_agent.execute(review_prompt, {})

        # Record invocation
        state["agent_invocations"].append(
            AgentInvocation(
                agent_role=AgentRole.REVIEWER,
                input=review_prompt[:200] + "...",
                output=output,
                timestamp=invocation_start,
            )
        )

        state["messages"].append(
            AIMessage(content=f"Review complete: Quality assessment done")
        )

        # Store review output
        state["session_data"]["review_output"] = output

        return state

    async def _report_node(self, state: SWEAgentState) -> SWEAgentState:
        """Execute reporting phase."""
        logger.info("Executing reporter agent")

        invocation_start = time.time()

        # Compile all outputs
        research_output = state["session_data"].get("research_output", "")
        code_output = state["session_data"].get("code_output", "")
        debug_output = state["session_data"].get("debug_output", "")
        review_output = state["session_data"].get("review_output", "")

        report_prompt = f"""Compile a comprehensive technical report for the completed task:

Task: {state['request'].task}

Research Findings:
{research_output[:1000]}...

Implementation:
{code_output[:1500]}...

Debug Report:
{debug_output[:1000]}...

Quality Review:
{review_output[:1000]}...

Create a structured technical report following the template:
- Executive Summary
- Task Breakdown
- Research Findings
- Implementation Details
- Testing & Debugging
- Quality Assurance
- Final Deliverables
- Verification Steps
- Next Steps

Make it clear, actionable, and reproducible."""

        # Execute reporter agent
        output = await self.reporter_agent.execute(report_prompt, {})

        # Record invocation
        state["agent_invocations"].append(
            AgentInvocation(
                agent_role=AgentRole.REPORTER,
                input=report_prompt[:200] + "...",
                output=output,
                timestamp=invocation_start,
            )
        )

        state["messages"].append(
            AIMessage(content=f"Technical report generated")
        )

        # Store final report
        state["final_output"] = output

        return state

    async def _finalize_node(self, state: SWEAgentState) -> SWEAgentState:
        """Finalize the workflow."""
        logger.info("Finalizing SWE workflow")

        state["messages"].append(
            AIMessage(
                content=f"Workflow complete. "
                f"Agents invoked: {len(state['agent_invocations'])}"
            )
        )

        return state
