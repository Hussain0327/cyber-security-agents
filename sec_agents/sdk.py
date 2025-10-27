import asyncio
from typing import Optional, Dict, Any
import logging

from .core.swe_graph import SWEOrchestrator
from .core.swe_models import SWERequest, SWEResponse
from .core.memory import get_memory_store

logger = logging.getLogger(__name__)


class SWEClient:

    def __init__(
        self,
        provider: str = "openai",
        model_name: Optional[str] = None,
        session_id: str = "default",
        max_iterations: int = 50,
    ):

        self.provider = provider
        self.model_name = model_name
        self.session_id = session_id
        self.max_iterations = max_iterations
        self.memory_store = get_memory_store()

        self._orchestrator = SWEOrchestrator(
            provider_type=provider,
            model_name=model_name
        )

    async def execute(
        self,
        task: str,
        context: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> SWEResponse:

        request = SWERequest(
            task=task,
            session_id=session_id or self.session_id,
            context=context,
            max_iterations=self.max_iterations,
            provider=provider or self.provider,
            model_name=self.model_name,
        )

        logger.info(f"Executing task: {task[:100]}...")
        result = await self._orchestrator.execute(request)

        return result

    def execute_sync(
        self,
        task: str,
        context: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> SWEResponse:

        return asyncio.run(
            self.execute(task, context, provider, session_id)
        )

    def get_session_history(
        self,
        session_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> list[Dict[str, str]]:
        sid = session_id or self.session_id
        return self.memory_store.get_messages(sid, limit=limit)

    def get_session_info(
        self,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        sid = session_id or self.session_id
        return self.memory_store.get_session_info(sid)

    def clear_session(
        self,
        session_id: Optional[str] = None
    ) -> bool:
        
        sid = session_id or self.session_id
        return self.memory_store.clear_session(sid)

    def list_sessions(self) -> list[str]:
        return self.memory_store.list_sessions()


# Convenience function for quick one-off tasks
async def execute_task(
    task: str,
    provider: str = "openai",
    model_name: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> SWEResponse:
    """
    Execute a one-off SWE task without managing a client instance.

    Args:
        task: The software engineering task
        provider: LLM provider (openai, anthropic, local)
        model_name: Specific model to use
        context: Optional task context

    Returns:
        SWEResponse with results

    Example:
        ```python
        result = await execute_task(
            "Create a Python function to validate email addresses"
        )
        print(result.report)
        ```
    """
    client = SWEClient(provider=provider, model_name=model_name)
    return await client.execute(task, context=context)


def execute_task_sync(
    task: str,
    provider: str = "openai",
    model_name: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> SWEResponse:
    """
    Synchronous version of execute_task().

    Args:
        task: The software engineering task
        provider: LLM provider (openai, anthropic, local)
        model_name: Specific model to use
        context: Optional task context

    Returns:
        SWEResponse with results

    Example:
        ```python
        result = execute_task_sync(
            "Create a Python function to validate email addresses"
        )
        print(result.report)
        ```
    """
    return asyncio.run(execute_task(task, provider, model_name, context))
