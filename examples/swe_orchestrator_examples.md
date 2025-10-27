# SWE Multi-Agent Orchestrator Examples

This guide provides comprehensive examples of using the SWE Multi-Agent Orchestrator through different interfaces.

## Overview

The SWE Orchestrator coordinates 5 specialized AI agents to complete end-to-end software engineering workflows:

1. **Research Agent** - Gathers verified technical information and documentation
2. **Developer Agent** - Writes production-ready, well-documented code
3. **Debugger Agent** - Tests implementations and identifies issues
4. **Reviewer Agent** - Performs quality assurance and security review
5. **Reporter Agent** - Compiles comprehensive technical reports

## Table of Contents

- [Python SDK Usage](#python-sdk-usage)
- [REST API Usage](#rest-api-usage)
- [CLI Usage](#cli-usage)
- [Common Use Cases](#common-use-cases)

---

## Python SDK Usage

### Basic Example

```python
import asyncio
from sec_agents.sdk import SWEClient

async def main():
    # Create a client
    client = SWEClient(provider="openai")

    # Execute a task
    result = await client.execute(
        "Create a Python function to validate email addresses with regex"
    )

    # Print the technical report
    print(result.report)
    print(f"\nCompleted in {result.execution_time_seconds:.2f}s")
    print(f"Agents invoked: {len(result.agent_invocations)}")

if __name__ == "__main__":
    asyncio.run(main())
```

### With Session Continuity

```python
import asyncio
from sec_agents.sdk import SWEClient

async def main():
    # Create a client with a named session
    client = SWEClient(
        provider="openai",
        session_id="my-flask-api-project"
    )

    # First task
    result1 = await client.execute(
        "Create a Flask REST API with a /users endpoint"
    )
    print("Step 1 Complete:", result1.status)

    # Second task builds on the first (uses session context)
    result2 = await client.execute(
        "Now add authentication to the API using JWT tokens"
    )
    print("Step 2 Complete:", result2.status)

    # Third task
    result3 = await client.execute(
        "Add comprehensive error handling and input validation"
    )
    print("Step 3 Complete:", result3.status)

    # View session history
    history = client.get_session_history()
    print(f"\nSession has {len(history)} messages")

if __name__ == "__main__":
    asyncio.run(main())
```

### Synchronous Usage (Non-Async Code)

```python
from sec_agents.sdk import execute_task_sync

# One-off synchronous task
result = execute_task_sync(
    "Create a Python decorator for rate limiting API requests"
)

print(result.report)
```

### With Anthropic Claude

```python
import asyncio
from sec_agents.sdk import SWEClient

async def main():
    # Use Anthropic Claude instead of OpenAI
    client = SWEClient(
        provider="anthropic",
        model_name="claude-3-sonnet-20240229"
    )

    result = await client.execute(
        "Build a Python script to parse CSV files and generate reports"
    )

    print(result.report)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## REST API Usage

### Basic Request

```bash
# Generate authentication token
TOKEN=$(python -m sec_agents.cli auth | grep -oP 'Bearer \K.*')

# Execute a task
curl -X POST http://localhost:8000/swe/orchestrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task": "Create a RESTful API in Flask with user CRUD operations",
    "session_id": "my-session",
    "provider": "openai"
  }'
```

### Python Requests

```python
import requests
from sec_agents.app.auth import generate_demo_token

# Generate token
token = generate_demo_token()

# Execute task
response = requests.post(
    "http://localhost:8000/swe/orchestrate",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "task": "Create a Python data validation library with Pydantic",
        "session_id": "data-validator-project",
        "provider": "openai",
        "max_iterations": 50
    }
)

result = response.json()
print(result["report"])
```

### Session Management

```python
import requests
from sec_agents.app.auth import generate_demo_token

token = generate_demo_token()
headers = {"Authorization": f"Bearer {token}"}

# Get session info
response = requests.get(
    "http://localhost:8000/swe/session/my-session",
    headers=headers
)
session_info = response.json()
print(f"Messages in session: {len(session_info['messages'])}")

# Continue existing session
response = requests.post(
    "http://localhost:8000/swe/session/my-session/continue",
    headers=headers,
    json={"task": "Add unit tests for the validator"}
)

# List all sessions
response = requests.get(
    "http://localhost:8000/swe/sessions",
    headers=headers
)
print(f"Active sessions: {response.json()['count']}")

# Clear a session
response = requests.delete(
    "http://localhost:8000/swe/session/my-session",
    headers=headers
)
```

---

## CLI Usage

### Basic Task Execution

```bash
# Execute a simple task
python -m sec_agents.cli --provider openai swe run \
  "Create a Python function to calculate Fibonacci numbers"

# Save output to file
python -m sec_agents.cli --provider openai swe run \
  "Build a simple HTTP server in Python" \
  --output report.md \
  --format markdown
```

### With Session Management

```bash
# Execute task with named session
python -m sec_agents.cli --provider openai swe run \
  "Create a Django REST API" \
  --session-id django-project

# Continue the session
python -m sec_agents.cli --provider openai swe run \
  "Add authentication to the API" \
  --session-id django-project

# View session info
python -m sec_agents.cli swe session django-project

# List all sessions
python -m sec_agents.cli swe sessions

# Clear a session
python -m sec_agents.cli swe session django-project --clear
```

### Different Providers

```bash
# Use OpenAI (default)
python -m sec_agents.cli --provider openai swe run "Create a web scraper"

# Use Anthropic Claude
python -m sec_agents.cli --provider anthropic swe run "Create a web scraper"

# Use local model (if configured)
python -m sec_agents.cli --provider local swe run "Create a web scraper"
```

---

## Common Use Cases

### 1. API Development

```python
import asyncio
from sec_agents.sdk import SWEClient

async def build_api():
    client = SWEClient(provider="openai", session_id="api-project")

    # Research best practices
    await client.execute(
        "Research best practices for building RESTful APIs in Python with Flask"
    )

    # Implement the API
    await client.execute(
        "Create a Flask API with endpoints for: GET /users, POST /users, "
        "GET /users/<id>, PUT /users/<id>, DELETE /users/<id>. "
        "Use SQLAlchemy for database operations."
    )

    # Add tests
    result = await client.execute(
        "Write comprehensive integration tests for the API using pytest"
    )

    print(result.report)

asyncio.run(build_api())
```

### 2. Data Processing Pipeline

```python
import asyncio
from sec_agents.sdk import SWEClient

async def build_pipeline():
    client = SWEClient(provider="openai", session_id="data-pipeline")

    result = await client.execute("""
        Create a Python data processing pipeline that:
        1. Reads CSV files from a directory
        2. Validates data using Pydantic models
        3. Transforms data (clean, normalize)
        4. Loads into a SQLite database
        5. Generates summary statistics

        Include error handling, logging, and unit tests.
    """)

    print(result.report)

asyncio.run(build_pipeline())
```

### 3. Code Review and Refactoring

```python
import asyncio
from sec_agents.sdk import SWEClient

async def review_code():
    client = SWEClient(provider="openai")

    code_to_review = """
    def process_data(data):
        result = []
        for item in data:
            if item['value'] > 0:
                result.append(item['value'] * 2)
        return result
    """

    result = await client.execute(f"""
        Review and refactor this Python code:

        {code_to_review}

        Please:
        1. Identify any issues or improvements
        2. Refactor for better readability and performance
        3. Add type hints and documentation
        4. Suggest test cases
    """)

    print(result.report)

asyncio.run(review_code())
```

### 4. Documentation Generation

```python
import asyncio
from sec_agents.sdk import SWEClient

async def generate_docs():
    client = SWEClient(provider="openai")

    result = await client.execute("""
        Create comprehensive documentation for a Python library that provides:
        - User authentication
        - Session management
        - Rate limiting

        Include:
        1. README with installation and quick start
        2. API reference documentation
        3. Usage examples
        4. Contribution guidelines
    """)

    print(result.report)

asyncio.run(generate_docs())
```

### 5. Algorithm Implementation

```bash
python -m sec_agents.cli --provider openai swe run \
  "Implement Dijkstra's shortest path algorithm in Python with:
   1. Clean, well-documented code
   2. Time and space complexity analysis
   3. Visualization of the algorithm
   4. Unit tests with edge cases
   5. Performance benchmarks" \
  --output dijkstra_report.md
```

---

## Advanced Features

### Custom Context

```python
import asyncio
from sec_agents.sdk import SWEClient

async def with_context():
    client = SWEClient(provider="openai")

    result = await client.execute(
        "Create database models for the user management system",
        context={
            "framework": "Django",
            "database": "PostgreSQL",
            "requirements": [
                "User authentication",
                "Role-based permissions",
                "Activity logging"
            ]
        }
    )

    print(result.report)

asyncio.run(with_context())
```

### Iterative Development

```python
import asyncio
from sec_agents.sdk import SWEClient

async def iterative_development():
    client = SWEClient(
        provider="openai",
        session_id="todo-app",
        max_iterations=50
    )

    # Phase 1: Core functionality
    await client.execute("Create a CLI todo app in Python with add/list/remove")

    # Phase 2: Persistence
    await client.execute("Add SQLite database persistence to the todo app")

    # Phase 3: Features
    await client.execute("Add due dates and priority levels to todos")

    # Phase 4: Polish
    result = await client.execute("Add colored output and better formatting")

    print("\nFinal Report:")
    print(result.report)

asyncio.run(iterative_development())
```

---

## Tips and Best Practices

1. **Use Descriptive Tasks**: Be specific about requirements, constraints, and desired outcomes
2. **Leverage Sessions**: Use session continuity for multi-step projects
3. **Specify Context**: Provide relevant context (frameworks, libraries, requirements)
4. **Review Outputs**: The orchestrator provides comprehensive reports - review them carefully
5. **Iterative Refinement**: Break complex tasks into smaller steps
6. **Provider Selection**: Choose the appropriate LLM provider for your needs

---

## Troubleshooting

### API Key Not Found

```bash
# Set your API keys
export OPENAI_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"
```

### Session Not Found

Sessions are stored in-memory and will be lost when the server restarts. For persistent sessions, save the outputs and recreate context when needed.

### Timeout Issues

For very complex tasks, increase the max_iterations:

```python
client = SWEClient(max_iterations=100)
```

---

## Next Steps

- Explore the [API Documentation](../sec_agents/app/main.py)
- Check out the [Agent Architecture](../sec_agents/core/swe_agents.py)
- Review the [Models and Types](../sec_agents/core/swe_models.py)
- See the [n8n Workflow](../n8n.json) that inspired this implementation
