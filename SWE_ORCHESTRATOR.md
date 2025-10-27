# SWE Multi-Agent Orchestrator

**A production-ready implementation of the n8n multi-agent software engineering orchestrator**

## 🎯 Overview

This is a complete port of your n8n multi-agent workflow into a flexible, open-source Python framework integrated with the existing cybersecurity agents platform. The orchestrator coordinates 5 specialized AI agents to complete end-to-end software engineering tasks.

## 🏗️ Architecture

### Specialized Agents

1. **Research Agent** (`sec_agents/core/swe_agents.py`)
   - Gathers verified technical information and documentation
   - Checks version compatibility and best practices
   - Provides source links for all claims
   - Flags uncertain information

2. **Developer Agent** (`sec_agents/core/swe_agents.py`)
   - Writes production-ready code following SOLID principles
   - Implements proper error handling and validation
   - Adds comprehensive documentation
   - Considers security, performance, and scalability

3. **Debugger Agent** (`sec_agents/core/swe_agents.py`)
   - Reviews code and outputs for bugs
   - Tests implementations against requirements
   - Identifies edge cases and failure scenarios
   - Proposes specific fixes with explanations

4. **Reviewer Agent** (`sec_agents/core/swe_agents.py`)
   - Fact-checks all technical claims
   - Validates assumptions and logic
   - Enforces coding standards and best practices
   - Reviews for security vulnerabilities

5. **Reporter Agent** (`sec_agents/core/swe_agents.py`)
   - Compiles all outputs into unified technical reports
   - Structures information logically
   - Ensures all claims have supporting evidence
   - Makes reports actionable and reproducible

### Core Components

```
sec_agents/
├── core/
│   ├── swe_models.py        # Data models (Request, Response, State)
│   ├── swe_agents.py        # 5 specialized agent implementations
│   ├── swe_graph.py         # LangGraph orchestrator workflow
│   └── memory.py            # Session-based conversation memory
├── tools/
│   └── code_executor.py     # Safe code execution sandbox
├── app/
│   └── main.py             # FastAPI endpoints (updated)
├── sdk.py                   # Python SDK for programmatic access
└── cli.py                   # CLI commands (updated)
```

## 🚀 Usage

### Python SDK

```python
from sec_agents.sdk import SWEClient
import asyncio

async def main():
    client = SWEClient(provider="openai", session_id="my-project")

    result = await client.execute(
        "Create a REST API in Flask with user CRUD operations"
    )

    print(result.report)

asyncio.run(main())
```

### CLI

```bash
# Execute a task
python -m sec_agents.cli --provider openai swe run \
  "Build a Python data validator with tests"

# With session continuity
python -m sec_agents.cli --provider openai swe run \
  "Create a Flask API" --session-id my-api

python -m sec_agents.cli --provider openai swe run \
  "Add authentication" --session-id my-api

# Manage sessions
python -m sec_agents.cli swe sessions
python -m sec_agents.cli swe session my-api
```

### REST API

```bash
# Start the server
python -m sec_agents.cli serve --host 0.0.0.0 --port 8000

# Generate token
export TOKEN=$(python -m sec_agents.cli auth | grep -oP 'Bearer \K.*')

# Execute task
curl -X POST http://localhost:8000/swe/orchestrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task": "Create a RESTful API with Flask",
    "session_id": "my-session",
    "provider": "openai"
  }'
```

## 📋 Features Implemented

✅ **Complete n8n Architecture Port**
- All 5 specialized agents with original prompts
- Planner/orchestrator coordinating agent workflow
- Session-based memory (20 message window)
- Iterative refinement (max 50 iterations)

✅ **Additional Enhancements**
- Pluggable agent architecture for extensibility
- Support for OpenAI GPT-4o and Anthropic Claude
- Code execution sandbox for testing
- REST API, Python SDK, and CLI interfaces
- Comprehensive session management
- Structured data models with Pydantic

✅ **Production-Ready**
- FastAPI integration with authentication
- Async/await throughout for performance
- Comprehensive error handling
- Logging and tracing
- Type hints and documentation

✅ **Developer Experience**
- Complete documentation with examples
- Unit and integration tests
- Quick start examples
- Clear API documentation

## 🎨 Comparison with n8n Workflow

| Feature | n8n Workflow | This Implementation |
|---------|--------------|---------------------|
| **Specialized Agents** | 5 agents | ✅ Same 5 agents |
| **Orchestrator** | Planner Agent | ✅ SWEOrchestrator |
| **Memory** | Buffer Window (20) | ✅ SessionMemoryStore (20) |
| **Code Execution** | Code Tool | ✅ CodeExecutor |
| **Providers** | OpenAI (GPT-4o) | ✅ OpenAI + Anthropic |
| **Interface** | Webhook | ✅ REST API + SDK + CLI |
| **Session Management** | Session ID | ✅ Full session management |
| **Max Iterations** | 50 | ✅ Configurable (default 50) |
| **Agent Prompts** | Custom | ✅ Exact same prompts |
| **Output Format** | JSON | ✅ Structured + Markdown |

## 📁 Files Created

### Core Implementation
- `sec_agents/core/swe_models.py` - Request/response models and state management
- `sec_agents/core/swe_agents.py` - 5 specialized agent implementations
- `sec_agents/core/swe_graph.py` - Main orchestrator using LangGraph
- `sec_agents/core/memory.py` - Session memory management
- `sec_agents/tools/code_executor.py` - Code execution sandbox

### User Interfaces
- `sec_agents/sdk.py` - Python SDK for programmatic access
- `sec_agents/app/main.py` - Updated with SWE API endpoints
- `sec_agents/cli.py` - Updated with SWE CLI commands

### Documentation & Examples
- `examples/swe_orchestrator_examples.md` - Comprehensive usage guide
- `examples/swe_quickstart.py` - Runnable quick start examples
- `README.md` - Updated with SWE orchestrator information
- `SWE_ORCHESTRATOR.md` - This file

### Tests
- `sec_agents/evals/test_swe_orchestrator.py` - Test suite for orchestrator

## 🔧 Configuration

### Environment Variables

```bash
# Required for OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# Optional for Anthropic
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# Optional API configuration
export JWT_SECRET_KEY="your-jwt-secret"
export LOG_LEVEL="INFO"
```

### Provider Configuration

The orchestrator supports multiple LLM providers:

- **OpenAI** (default): `provider="openai"`, model: `gpt-4o`
- **Anthropic**: `provider="anthropic"`, model: `claude-3-sonnet-20240229`
- **Local**: `provider="local"` (for testing without API costs)

## 📊 API Endpoints

### SWE Orchestrator Endpoints

- `POST /swe/orchestrate` - Execute a software engineering task
- `GET /swe/session/{session_id}` - Get session info and message history
- `POST /swe/session/{session_id}/continue` - Continue existing session
- `DELETE /swe/session/{session_id}` - Clear session from memory
- `GET /swe/sessions` - List all active sessions

### Request Format

```json
{
  "task": "Create a REST API in Flask with user endpoints",
  "session_id": "my-session",
  "context": {
    "framework": "Flask",
    "database": "SQLite"
  },
  "max_iterations": 50,
  "provider": "openai",
  "model_name": "gpt-4o"
}
```

### Response Format

```json
{
  "request_id": "uuid",
  "session_id": "my-session",
  "task": "Create a REST API...",
  "status": "completed",
  "report": "# Technical Report...",
  "agent_invocations": [...],
  "iterations_used": 5,
  "execution_time_seconds": 45.2,
  "timestamp": "2024-01-15T10:30:00"
}
```

## 🧪 Testing

```bash
# Run all tests
python -m sec_agents.cli test

# Run SWE orchestrator tests specifically
pytest sec_agents/evals/test_swe_orchestrator.py -v

# Run integration tests
pytest sec_agents/evals/test_swe_orchestrator.py -m integration

# Run with slow tests (uses real API providers)
pytest sec_agents/evals/test_swe_orchestrator.py --run-slow
```

## 📖 Examples

See `examples/swe_orchestrator_examples.md` for comprehensive examples including:

- Basic task execution
- Session-based multi-step development
- API development workflows
- Data processing pipelines
- Code review and refactoring
- Documentation generation
- Algorithm implementation

Run the quick start:

```bash
python examples/swe_quickstart.py
```

## 🛠️ Development

### Adding Custom Agents

```python
from sec_agents.core.swe_agents import SWEAgent

class CustomAgent(SWEAgent):
    def __init__(self, provider):
        super().__init__(provider, "custom")

    def get_system_prompt(self) -> str:
        return "Your custom agent prompt..."

    async def execute(self, input_data, context):
        # Your implementation
        pass
```

### Extending the Orchestrator

The orchestrator uses LangGraph, making it easy to add nodes, modify the workflow, or create conditional branches.

## 🚢 Deployment

### Docker (Future)

```bash
# Build image
docker build -t swe-orchestrator .

# Run container
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  swe-orchestrator
```

### Production Considerations

- **Session Persistence**: Current implementation uses in-memory storage. For production, implement Redis or database-backed storage
- **Rate Limiting**: Add rate limiting to prevent API abuse
- **Monitoring**: Integrate with APM tools for performance monitoring
- **Scaling**: Run multiple workers behind a load balancer
- **Caching**: Cache research results and common patterns

## 🎯 Roadmap

- [ ] Persistent session storage (Redis/PostgreSQL)
- [ ] Web UI for task management
- [ ] Agent performance metrics and analytics
- [ ] Custom agent plugin system
- [ ] Parallel agent execution for independent tasks
- [ ] Integration with GitHub for PR reviews
- [ ] Real-time streaming of agent outputs
- [ ] Fine-tuned models for specific domains

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional specialized agents (Testing, Deployment, Documentation)
- Enhanced code execution sandbox with more languages
- Better error recovery and retry logic
- Performance optimizations
- Additional LLM provider integrations

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

Based on the n8n multi-agent orchestrator workflow, adapted and enhanced for production use as an open-source Python framework.

---

**Built with:** Python 3.11+, LangGraph, FastAPI, Pydantic, OpenAI, Anthropic
