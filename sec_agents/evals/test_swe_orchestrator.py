"""
Tests for the SWE Multi-Agent Orchestrator.

Tests the core functionality of the orchestrator, specialized agents,
and integration with the API and SDK.
"""

import pytest
import asyncio
from sec_agents.sdk import SWEClient, execute_task
from sec_agents.core.swe_graph import SWEOrchestrator
from sec_agents.core.swe_models import SWERequest
from sec_agents.core.memory import get_memory_store
from sec_agents.tools.code_executor import CodeExecutor


class TestCodeExecutor:
    """Test the code execution tool."""

    @pytest.mark.asyncio
    async def test_python_execution(self):
        """Test executing Python code."""
        executor = CodeExecutor()

        result = await executor.execute_python("""
print("Hello, World!")
x = 2 + 2
print(f"2 + 2 = {x}")
""")

        assert result["success"] is True
        assert "Hello, World!" in result["stdout"]
        assert "2 + 2 = 4" in result["stdout"]
        assert result["return_code"] == 0

    @pytest.mark.asyncio
    async def test_python_with_error(self):
        """Test Python code with errors."""
        executor = CodeExecutor()

        result = await executor.execute_python("""
x = 1 / 0  # Division by zero
""")

        assert result["success"] is False
        assert "ZeroDivisionError" in result["stderr"]

    @pytest.mark.asyncio
    async def test_python_with_variables(self):
        """Test injecting variables into Python code."""
        executor = CodeExecutor()

        result = await executor.execute_python(
            "print(f'Name: {name}, Age: {age}')",
            variables={"name": "Alice", "age": 30}
        )

        assert result["success"] is True
        assert "Name: Alice, Age: 30" in result["stdout"]


class TestSessionMemory:
    """Test the session memory system."""

    def test_create_session(self):
        """Test creating a new session."""
        store = get_memory_store()
        session_id = "test-session-1"

        session = store.get_session(session_id)

        assert session["session_id"] == session_id
        assert session["messages"] == []
        assert session["message_count"] == 0

    def test_add_messages(self):
        """Test adding messages to a session."""
        store = get_memory_store()
        session_id = "test-session-2"

        store.add_message(session_id, "user", "Hello")
        store.add_message(session_id, "assistant", "Hi there!")

        messages = store.get_messages(session_id)

        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "Hello"
        assert messages[1]["role"] == "assistant"

    def test_message_window(self):
        """Test sliding window for messages."""
        store = get_memory_store()
        store.max_messages_per_session = 5
        session_id = "test-session-3"

        # Add 10 messages
        for i in range(10):
            store.add_message(session_id, "user", f"Message {i}")

        messages = store.get_messages(session_id)

        # Should only keep last 5
        assert len(messages) <= 5
        assert messages[-1]["content"] == "Message 9"

    def test_session_context(self):
        """Test session context storage."""
        store = get_memory_store()
        session_id = "test-session-4"

        store.update_context(session_id, {"project": "test", "version": "1.0"})
        context = store.get_context(session_id)

        assert context["project"] == "test"
        assert context["version"] == "1.0"

    def test_clear_session(self):
        """Test clearing a session."""
        store = get_memory_store()
        session_id = "test-session-5"

        store.add_message(session_id, "user", "Test")
        assert session_id in store.list_sessions()

        cleared = store.clear_session(session_id)
        assert cleared is True
        assert session_id not in store.list_sessions()


@pytest.mark.integration
class TestSWEOrchestrator:
    """Integration tests for the SWE orchestrator."""

    @pytest.mark.asyncio
    async def test_simple_task_local_provider(self):
        """Test executing a simple task with local provider."""
        # Use local provider to avoid API costs in tests
        orchestrator = SWEOrchestrator(provider_type="local")

        request = SWERequest(
            task="Create a simple Python function to add two numbers",
            session_id="test-orchestrator-1",
            max_iterations=10
        )

        result = await orchestrator.execute(request)

        assert result.status in ["completed", "partial"]
        assert result.session_id == "test-orchestrator-1"
        assert result.task == request.task
        assert len(result.report) > 0
        assert result.iterations_used > 0

    @pytest.mark.asyncio
    async def test_session_continuity(self):
        """Test that sessions maintain context."""
        orchestrator = SWEOrchestrator(provider_type="local")
        session_id = "test-continuity"

        # First task
        request1 = SWERequest(
            task="Create a calculator class",
            session_id=session_id
        )
        result1 = await orchestrator.execute(request1)

        # Second task in same session
        request2 = SWERequest(
            task="Add a square root method",
            session_id=session_id
        )
        result2 = await orchestrator.execute(request2)

        # Both should use the same session
        assert result1.session_id == result2.session_id

        # Check that memory store has the conversation
        store = get_memory_store()
        messages = store.get_messages(session_id)
        assert len(messages) >= 2


@pytest.mark.integration
class TestSWEClient:
    """Integration tests for the SWE client SDK."""

    @pytest.mark.asyncio
    async def test_client_execute(self):
        """Test executing a task with the SDK client."""
        client = SWEClient(provider="local", session_id="test-client-1")

        result = await client.execute(
            "Create a function to check if a number is prime"
        )

        assert result.status in ["completed", "partial"]
        assert len(result.report) > 0

    @pytest.mark.asyncio
    async def test_client_session_management(self):
        """Test session management via SDK."""
        client = SWEClient(provider="local", session_id="test-client-2")

        # Execute a task
        await client.execute("Create a hello world function")

        # Get session history
        history = client.get_session_history()
        assert len(history) > 0

        # Get session info
        info = client.get_session_info()
        assert info["session_id"] == "test-client-2"
        assert info["message_count"] > 0

        # Clear session
        cleared = client.clear_session()
        assert cleared is True

    @pytest.mark.asyncio
    async def test_execute_task_convenience(self):
        """Test the convenience function."""
        result = await execute_task(
            "Create a simple greeting function",
            provider="local"
        )

        assert result.status in ["completed", "partial"]
        assert len(result.report) > 0


# Mark slow tests
@pytest.mark.slow
@pytest.mark.skipif(
    "not config.getoption('--run-slow')",
    reason="Slow test, only run with --run-slow"
)
class TestSWEWithRealProviders:
    """Tests that use real API providers (OpenAI, Anthropic)."""

    @pytest.mark.asyncio
    async def test_openai_simple_task(self):
        """Test with OpenAI provider."""
        # Only run if OPENAI_API_KEY is set
        import os
        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("OPENAI_API_KEY not set")

        client = SWEClient(provider="openai")
        result = await client.execute(
            "Create a Python function to validate email addresses"
        )

        assert result.status == "completed"
        assert "email" in result.report.lower()
        assert len(result.agent_invocations) >= 5  # All agents should run


def pytest_addoption(parser):
    """Add custom pytest options."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests that use real API providers"
    )
