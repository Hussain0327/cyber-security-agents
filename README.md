# SWE Security Orchestrator
A unified platform for two things:

1. Security analysis (log triage, incident response support, threat mapping).
2. Multi-agent software engineering (research → build → test → review → report).

Status: v1. This came out of my original multi-agent n8n automation setup (research agent + automation workforce). I rewrote it in Python so it’s easier to extend, version, and ship.

I want feedback. I want people to fork it. If you break it or improve it, open a PR with what you changed and why.

---

## Table of Contents

* [What this project is](#what-this-project-is)
* [What you get](#what-you-get)
* [Quick links](#quick-links)
* [Install](#install)
* [Quick start](#quick-start)

  * [SWE Orchestrator](#swe-orchestrator)
  * [Security Analysis](#security-analysis)
* [Architecture](#architecture)
* [How the SWE Orchestrator works](#how-the-swe-orchestrator-works)
* [How the Security Analysis works](#how-the-security-analysis-works)
* [API reference](#api-reference)
* [CLI reference](#cli-reference)
* [Configuration](#configuration)
* [Development / extending this](#development--extending-this)
* [Deployment notes / hard truth](#deployment-notes--hard-truth)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)

---

## What this project is

This repo gives you:

* A security analysis graph that can take raw security data (logs, alerts, suspected malware behavior, etc.), classify what’s happening, map it to MITRE ATT&CK techniques, and suggest next steps.
* A multi-agent “software engineer in a box” that can plan, write code, run the code in a sandbox, debug, review for quality/security, and then hand you a final report. It keeps session memory so you can iterate the same project across multiple calls.

You can use all of this three ways:

* Python SDK
* CLI
* REST API (FastAPI)

Providers: OpenAI, Anthropic, or local models. You choose at runtime.

This is not “chatbot plays pretend engineer.” The point is repeatable workflows with clear outputs.

---

## What you get

### Security side

* Log triage and anomaly review
* Help with incident response
* Threat hunting patterns
* Malware behavior analysis
* Vulnerability assessment
* MITRE ATT&CK mapping
* Sigma rule generation

### SWE side

* Research best practices for a requested feature
* Write production-style code
* Run tests / debug
* Do review with security focus
* Deliver a clean written report (what was built, how it works, what to do next)

### Platform features

* FastAPI app with JWT auth
* Session memory per project / session_id
* Code execution sandbox for generated code
* Tracing / logging hooks
* CLI, SDK, REST, all hitting the same core

---

## Quick links

* Complete Guide: this README
* SWE architecture: `sec_agents/core/swe_graph.py`, `sec_agents/core/swe_agents.py`
* Deployment: see [Deployment notes / hard truth](#deployment-notes--hard-truth) and Docker section
* Examples: `examples/`
* Contributing: [Contributing](#contributing)

---

## Install

Prereqs:

* Python 3.11+
* Git
* pip

```bash
# Clone
git clone <repository-url>
cd cybersecurity-agents

# Install
pip install -e .

# Env vars
cp .env.example .env
# then edit .env with your API keys, secrets, etc.
```

What gets installed:

* LangGraph / LangChain for orchestration
* FastAPI + Uvicorn for the API server
* Pydantic for typed models
* Click for the CLI
* OpenAI / Anthropic provider support

---

## Quick start

### 1. Set your keys

Edit `.env`:

```bash
OPENAI_API_KEY=your-openai-key-here
ANTHROPIC_API_KEY=your-anthropic-key-here   # optional
JWT_SECRET_KEY=your-secret-key
LOG_LEVEL=INFO
```

### 2. Run the server and get a token

```bash
# Start API server
python -m sec_agents.cli serve --host 0.0.0.0 --port 8000

# In another terminal: generate JWT
python -m sec_agents.cli auth
```

You’ll use that token for any REST calls.

---

### SWE Orchestrator

Ask the system to build something for you.

Python SDK:

```python
from sec_agents.sdk import SWEClient
import asyncio

async def main():
    client = SWEClient(provider="openai", session_id="my-project")
    result = await client.execute(
        "Create a REST API in Flask with user authentication"
    )
    print(result.report)

asyncio.run(main())
```

CLI:

```bash
python -m sec_agents.cli --provider openai swe run \
  "Create a Python function to validate email addresses"
```

REST API:

```bash
# Start server first if it's not already running
python -m sec_agents.cli serve

# Then:
curl -X POST http://localhost:8000/swe/orchestrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task": "Create a calculator class",
    "provider": "openai",
    "session_id": "calc-session",
    "max_iterations": 50
  }'
```

Multi-step development with memory:

```python
async def multi_step():
    client = SWEClient(provider="openai", session_id="api-project")

    await client.execute("Create a Flask REST API")
    await client.execute("Add JWT authentication")
    result = await client.execute("Write integration tests")

    print(result.report)
    history = client.get_session_history()
    print(f"Session messages: {len(history)}")
```

---

### Security Analysis

Basic log triage example:

```python
from sec_agents.core.graph import SecurityGraph
from sec_agents.core.models import AnalysisRequest, AnalysisType
import asyncio

async def analyze_logs():
    graph = SecurityGraph(provider_type="openai")
    req = AnalysisRequest(
        analysis_type=AnalysisType.LOG_TRIAGE,
        data={"raw_log": "EventID=4688 ProcessName=powershell.exe /encodedcommand ..."}
    )
    result = await graph.analyze(req)
    print("Threat Level:", result.threat_level)
    print("MITRE Techniques:", result.mitre_techniques)
    print("Recommendations:", result.recommendations)

asyncio.run(analyze_logs())
```

CLI:

```bash
# list available scenarios
python -m sec_agents.cli list

# run a built-in scenario
python -m sec_agents.cli --provider openai run log_triage

# ad-hoc analysis with your own data
python -m sec_agents.cli --provider openai analyze log_triage \
  --data '{"raw_log": "EventID=4688 ProcessName=powershell.exe"}'
```

What the security side can return:

* Likely threat level
* Suspected technique(s) mapped to MITRE ATT&CK
* Suggested response steps
* Draft Sigma rules to detect similar activity again

---

## Architecture

Directory layout:

```text
cybersecurity-agents/
├── sec_agents/
│   ├── app/                  # FastAPI app
│   │   ├── main.py           # API endpoints
│   │   ├── auth.py           # JWT auth
│   │   └── tracing.py        # request tracing/logging hooks
│   ├── core/
│   │   ├── graph.py          # Security analysis graph
│   │   ├── models.py         # Shared data models
│   │   ├── swe_graph.py      # SWE orchestrator core
│   │   ├── swe_agents.py     # All SWE agents
│   │   ├── swe_models.py     # SWE data models
│   │   └── memory.py         # Session memory
│   ├── tools/
│   │   ├── code_executor.py  # sandboxed code execution
│   │   ├── parsers.py        # log / data parsing helpers
│   │   ├── sigma_builder.py  # Sigma rule generation
│   │   └── mitre_mapper.py   # MITRE ATT&CK mapping
│   ├── scenarios/            # security scenarios
│   ├── evals/                # tests
│   └── cli.py                # CLI entry point
├── examples/                 # usage examples
├── setup.py
└── requirements.txt
```

Key building blocks:

* SWE Orchestrator: multi-agent software workflow
* Security Graph: analysis pipeline for logs/incidents
* Session Memory: keeps context across calls
* Code Executor: runs generated code in isolation

---

## How the SWE Orchestrator works

High level flow:

```text
User task
   ↓
Orchestrator
   ↓
Research Agent      -> gather best practices, relevant patterns
Developer Agent     -> write actual code / implementation
Debugger Agent      -> run / test / find failures
Reviewer Agent      -> check quality, security, completeness
Reporter Agent      -> generate final summary + next steps
   ↓
You get code + a written report you can read
```

Why this matters:

* It forces review and testing, not just code dumping.
* You can iterate on the same session_id and build a project incrementally.
* You get an auditable output (the report) that you can hand to someone else.

Provider options:

* `"openai"` (ex: GPT-4o)
* `"anthropic"` (ex: Claude Sonnet)
* `"local"` (for testing with local models)

Config knobs:

* `session_id`: keeps memory between steps
* `max_iterations`: safety cap for long tasks
* optional `context`: structured extra info you want every agent to see

---

## How the Security Analysis works

The security side can run in different modes:

* Log triage
* Incident response assist
* Threat hunting
* Malware analysis
* Vulnerability assessment

For each run, it:

1. Reads the input data (logs, behaviors, indicators).
2. Assesses severity / threat level.
3. Maps behavior to MITRE ATT&CK techniques.
4. Suggests response and mitigation steps.
5. (Optionally) drafts Sigma rules so you can alert faster next time.

What you get back looks like:

* `threat_level`
* `mitre_techniques`
* `recommendations`
* sometimes structured artifacts like detection rules

This lets you treat it like an on-demand security analyst that documents its reasoning.

---

## API reference

All endpoints expect a valid JWT in `Authorization: Bearer <token>`.

Get a token:

```bash
python -m sec_agents.cli auth
```

Health check:

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/health
```

### SWE endpoints

`POST /swe/orchestrate`
Run a software engineering task.

Request:

```json
{
  "task": "Create a function to validate emails",
  "session_id": "optional-session-id",
  "provider": "openai",
  "max_iterations": 50,
  "context": {}
}
```

Response:

```json
{
  "request_id": "uuid",
  "session_id": "session-id",
  "task": "...",
  "status": "completed",
  "report": "markdown report",
  "agent_invocations": [...],
  "execution_time_seconds": 45.2
}
```

Other SWE endpoints:

* `GET /swe/session/{session_id}` – session history
* `POST /swe/session/{session_id}/continue` – continue same project with a new instruction
* `DELETE /swe/session/{session_id}` – clear a session from memory
* `GET /swe/sessions` – list active sessions

### Security endpoints

* `POST /analyze` – run a security analysis job
* `GET /scenarios` – list built-in scenarios
* `POST /scenarios/{name}/run` – execute a scenario
* `GET /health` – simple health check

---

## CLI reference

Global flags:

```bash
--provider [openai|anthropic|local]
--verbose, -v
```

SWE usage:

```bash
# run a task
python -m sec_agents.cli --provider openai swe run "Create API"

# work in a named session (keeps memory)
python -m sec_agents.cli --provider openai swe run \
  "Create a calculator class" --session-id calc-project

python -m sec_agents.cli --provider openai swe run \
  "Add scientific functions" --session-id calc-project

# inspect / clear sessions
python -m sec_agents.cli swe sessions
python -m sec_agents.cli swe session calc-project
python -m sec_agents.cli swe session calc-project --clear
```

Security usage:

```bash
# list available scenarios
python -m sec_agents.cli list

# run a scenario
python -m sec_agents.cli --provider openai run log_triage

# ad-hoc log triage
python -m sec_agents.cli --provider openai analyze log_triage \
  --data '{"raw_log": "EventID=4688 ProcessName=powershell.exe"}'
```

Server / auth / tests:

```bash
python -m sec_agents.cli serve --host 0.0.0.0 --port 8000
python -m sec_agents.cli auth
pytest sec_agents/evals/ -v
pytest --cov=sec_agents sec_agents/evals/
```

---

## Configuration

Environment variables:

```bash
# Required
OPENAI_API_KEY=sk-...
JWT_SECRET_KEY=your-secret

# Optional
ANTHROPIC_API_KEY=sk-...
LOG_LEVEL=INFO
API_HOST=127.0.0.1
API_PORT=8000
```

Provider config in code:

```python
# OpenAI (default)
client = SWEClient(
    provider="openai",
    model_name="gpt-4o"
)

# Anthropic
client = SWEClient(
    provider="anthropic",
    model_name="claude-3-sonnet-20240229"
)

# Local mock / self-hosted model
client = SWEClient(provider="local")
```

Session config:

```python
client = SWEClient(
    provider="openai",
    session_id="my-project",
    max_iterations=50
)
```

---

## Development / extending this

You can add:

1. A new SWE agent
2. A new security scenario

### Custom SWE agent

```python
from sec_agents.core.swe_agents import SWEAgent

class CustomAgent(SWEAgent):
    def __init__(self, provider):
        super().__init__(provider, "custom")

    def get_system_prompt(self) -> str:
        return "Your custom agent prompt"

    async def execute(self, input_data, context):
        # Your logic here
        ...
```

### Custom security scenario

Create a YAML file in `scenarios/`:

```yaml
name: "Custom Scenario"
description: "What this scenario is supposed to analyze"
steps:
  - name: "analysis_step"
    analysis_type: "log_triage"
    input_data: {...}
    expected_output: {...}
```

Testing:

```bash
pytest sec_agents/evals/ -v
pytest sec_agents/evals/test_swe_orchestrator.py -v
pytest --cov=sec_agents
```

---

## Deployment notes

This is v1. Please read this before you drop it in prod.

1. **Auth / JWT**

   * There is JWT auth. You generate tokens via the CLI.
   * You must set a real `JWT_SECRET_KEY` in `.env` for anything exposed beyond localhost.

2. **Session storage**

   * Right now session memory is in-memory.
   * If the process restarts, context is gone.
   * If you need durability or horizontal scaling, you need to back memory with Redis/PostgreSQL. That’s on the roadmap.

3. **Sandbox / code execution**

   * There is a code execution step so the Debugger Agent can actually run code.
   * Do not expose that sandbox directly to untrusted users without locking it down further (namespaces, seccomp, container isolation, etc.).

4. **HTTPS / CORS / rate limiting**

   * You should terminate behind something that does HTTPS, handle rate limiting, and log/monitor usage.
   * CORS and rate limits are not production-hardened in this version.

5. **Performance**

   * Typical ballpark:

     * Log parsing: ~0.01s per batch
     * MITRE mapping: ~0.02s per finding
     * Sigma rule draft: ~0.05s per rule
     * SWE task: ~30–60 seconds depending on complexity and model
   * These are rough local numbers, not SLAs.

Bottom line: today this is best used as a local analyst/engineer assistant, lab tool, or internal service behind a trusted perimeter.

---

## Roadmap

Short-term:

* Persistent session storage (Redis/PostgreSQL)
* Web UI to inspect sessions, tasks, and output
* More provider options (more model backends)
* Live streaming of agent output instead of waiting for the final report
* Stronger sandbox isolation
* Per-agent performance metrics / trace timeline

Mid-term:

* Easier plug-in of company-specific policies/playbooks
* Role-based access control on the API
* Tighter incident response runbooks

If you care about any of these, open an issue with specifics.

---

## Contributing

How to help:

1. Fork the repo.
2. Make a branch with one focused change. Examples:

   * New analysis scenario for a specific log source
   * Better sandbox isolation
   * Fixing a bad assumption in one of the agents
   * Adding tests around a weak spot
3. Run the tests (`pytest`) and make sure they pass.
4. Open a PR. In the PR, explain:

   * What changed
   * Why it matters (time saved, risk reduced, clarity improved)
   * How you tested it

I will review honest, scoped contributions first. I care about:

* Security accuracy
* Developer experience
* Repeatability

If you just have feedback (design, naming, missing docs, pain using it), open an issue. Tell me what slowed you down. I actually want to hear it.

---

## License

MIT License. See `LICENSE` in the repo.

Use it, extend it, reship it. Just keep the license and be honest about what you changed.

