# SWE Security Orchestrator - Cloudflare Workers AI Edition

A multi-agent AI system for software engineering tasks, powered by Cloudflare Workers AI and Llama 3 8B Instruct. This orchestrator coordinates 5 specialized agents to complete end-to-end development workflows with research, implementation, debugging, review, and reporting.

## Project Origin & Evolution

This project is a **Cloudflare Workers AI implementation** of the original Python-based SWE Security Orchestrator. The original system was built using:
- Python with LangGraph/LangChain
- OpenAI GPT-4 and Anthropic Claude models
- FastAPI for REST API
- In-memory session management

### Why Port to Cloudflare Workers?

**Goal**: Create a serverless, edge-deployed version that:
- Runs on Cloudflare's global network for low latency
- Uses Workers AI for cost-effective inference
- Leverages Durable Objects for stateful sessions
- Requires no server maintenance
- Scales automatically
- Provides a built-in web UI

### What Was Adapted

**From Python/LangGraph to JavaScript/Cloudflare:**

| Original (Python) | Cloudflare Version |
|-------------------|-------------------|
| LangGraph workflow | Custom JavaScript orchestration |
| OpenAI/Anthropic APIs | Workers AI (Llama 3 8B) |
| FastAPI server | Cloudflare Worker |
| In-memory sessions | Durable Objects |
| Separate UI needed | Embedded HTML/CSS/JS |
| Regional deployment | Global edge network |

**What Stayed the Same:**
- 5-agent architecture (Research, Developer, Debugger, Reviewer, Reporter)
- Sequential workflow pattern
- Agent system prompts and responsibilities
- Session-based conversation memory (20-message window)
- Structured technical report output

## Features

- **5 Specialized AI Agents**: Research, Developer, Debugger, Reviewer, Reporter
- **Cloudflare Workers AI**: Runs on Llama 3 8B Instruct model
- **Durable Objects**: Stateful conversation management with session persistence
- **Built-in Web UI**: Simple chat interface for interacting with agents
- **Production-Ready**: Deployed on Cloudflare's global edge network
- **Cost-Effective**: Pay-per-use pricing with Workers AI

## Architecture

```
User Request
    ↓
Cloudflare Worker (Entry Point)
    ↓
Durable Object (Session Management)
    ↓
┌─────────────────────────────────────┐
│   Multi-Agent Workflow (Sequential) │
├─────────────────────────────────────┤
│  1. Research Agent                  │  ← Gathers verified information
│  2. Developer Agent                 │  ← Writes production code
│  3. Debugger Agent                  │  ← Tests & finds issues
│  4. Reviewer Agent                  │  ← Quality assurance
│  5. Reporter Agent                  │  ← Compiles final report
└─────────────────────────────────────┘
    ↓
Structured Technical Report
```

## Project Structure

```
/
├── src/
│   ├── worker.js           # Main Worker (entry point, routing, UI)
│   ├── durable_object.js   # Multi-agent orchestrator (5 agents)
│   └── ui/                 # (Future: separate UI assets)
├── README.md               # This file
├── PROMPTS.md              # All AI prompts used
├── DEPLOYMENT.md           # Deployment guide
├── SUBMISSION_CHECKLIST.md # Cloudflare submission checklist
├── wrangler.toml           # Cloudflare configuration
└── LICENSE                 # MIT License
```

## Prerequisites

- Node.js 16+ installed
- Cloudflare account (free tier works)
- Git (for cloning)

## Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/Hussain0327/cf_ai_swe_security_orchestrator.git
cd cf_ai_swe_security_orchestrator
```

### Step 2: Install Wrangler CLI

```bash
npm install -g wrangler
```

### Step 3: Authenticate with Cloudflare

```bash
wrangler login
```

This opens your browser to authenticate with your Cloudflare account.

### Step 4: Deploy to Cloudflare

```bash
npx wrangler deploy
```

**Output:**
```
Total Upload: 21.71 KiB / gzip: 6.98 KiB
Published swe-security-orchestrator
  https://swe-security-orchestrator.your-subdomain.workers.dev
```

Your orchestrator is now live!

## Development Workflow

### Run Locally

```bash
npx wrangler dev
```

This starts a local development server at `http://localhost:8787`

### Test the API

**Health Check:**
```bash
curl http://localhost:8787/health
```

**Send a Task:**
```bash
curl -X POST http://localhost:8787/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "Create a Python function to validate email addresses"}'
```

**Get Conversation History:**
```bash
curl http://localhost:8787/history
```

**Clear History:**
```bash
curl -X POST http://localhost:8787/clear
```

### View Real-time Logs

```bash
wrangler tail
```

Use this to debug issues and see what the AI is returning.

## API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI (HTML interface) |
| `/health` | GET | Health check & system info |
| `/chat` | POST | Send task to orchestrator |
| `/history` | GET | Get conversation history |
| `/clear` | POST | Clear conversation history |

### POST /chat

**Request:**
```json
{
  "input": "Create a REST API for user authentication"
}
```

**Response:**
```json
{
  "response": "# Technical Report: REST API for User Authentication...",
  "agent_invocations": [
    {
      "agent": "research",
      "execution_time_ms": 2341,
      "output_length": 1523
    },
    {
      "agent": "developer",
      "execution_time_ms": 4521,
      "output_length": 2891
    },
    {
      "agent": "debugger",
      "execution_time_ms": 3142,
      "output_length": 1876
    },
    {
      "agent": "reviewer",
      "execution_time_ms": 2987,
      "output_length": 1654
    },
    {
      "agent": "reporter",
      "execution_time_ms": 5234,
      "output_length": 4123
    }
  ],
  "execution_time_ms": 18456
}
```

## Usage Examples

### Web UI

1. Deploy your Worker: `npx wrangler deploy`
2. Open the URL provided (e.g., `https://your-worker.workers.dev`)
3. Type your request in the chat box
4. Watch the 5 agents work in sequence

### Programmatic Access

**JavaScript/Node.js:**
```javascript
const response = await fetch('https://your-worker.workers.dev/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    input: 'Build a calculator class in JavaScript'
  })
});

const data = await response.json();
console.log(data.response);
```

**Python:**
```python
import requests

response = requests.post(
    'https://your-worker.workers.dev/chat',
    json={'input': 'Create a data validation function'}
)

print(response.json()['response'])
```

**cURL:**
```bash
curl -X POST https://your-worker.workers.dev/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "Implement a binary search algorithm"}'
```

## Agent Capabilities

### 1. Research Agent
- Gathers verified technical documentation
- Checks version compatibility
- Identifies security considerations
- Provides official source links
- Confidence level assessment

### 2. Developer Agent
- Writes clean, production-ready code
- Follows SOLID principles
- Implements error handling
- Adds comprehensive documentation
- Considers scalability and security

### 3. Debugger Agent
- Tests implementations
- Identifies edge cases
- Finds logic errors
- Proposes specific fixes
- Suggests test cases

### 4. Reviewer Agent
- Fact-checks technical claims
- Validates assumptions
- Reviews for security vulnerabilities
- Enforces coding standards
- Provides APPROVED/NEEDS REVISION assessment

### 5. Reporter Agent
- Compiles comprehensive technical reports
- Structures information logically
- Ensures reproducibility
- Includes verification steps
- Recommends next actions

## Configuration

### wrangler.toml

Key settings:

```toml
name = "swe-security-orchestrator"
main = "src/worker.js"
compatibility_date = "2024-01-01"

# Workers AI binding
[ai]
binding = "AI"

# Durable Objects
[[durable_objects.bindings]]
name = "SWE_ORCHESTRATOR"
class_name = "SWEOrchestrator"
script_name = "swe-security-orchestrator"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["SWEOrchestrator"]
```

### Session Management

Sessions are isolated by `session_id` parameter:

```bash
# Session 1
curl http://localhost:8787/chat?session_id=project-a -d '{"input": "..."}'

# Session 2 (separate history)
curl http://localhost:8787/chat?session_id=project-b -d '{"input": "..."}'
```

### Memory Window

- **Rolling Window**: Last 20 messages preserved
- **Storage**: Durable Objects (persistent across requests)
- **Eviction**: Automatic when limit reached

## Performance

| Metric | Value |
|--------|-------|
| Average Workflow Time | 17-50 seconds |
| Agent Invocations | 5 per task |
| Token Usage | ~5000-12000 per task |
| Cold Start | <1 second |
| Geographic Latency | <100ms (edge) |

**Optimization Tips:**
- Use session IDs to maintain context
- Keep tasks focused and specific
- Break complex projects into subtasks

## Security Considerations

### Current Implementation
- CORS enabled for browser access
- Session isolation via Durable Objects
- No authentication required (demo mode)

### Production Recommendations
- Add API key authentication
- Implement rate limiting
- Add request validation
- Enable Cloudflare Access for UI
- Monitor usage with Analytics

**Example: Add API Key Auth**
```javascript
if (request.headers.get('Authorization') !== `Bearer ${env.API_KEY}`) {
  return new Response('Unauthorized', { status: 401 });
}
```

## Cost Estimation

Cloudflare Workers AI pricing (as of 2024):

| Component | Free Tier | Paid |
|-----------|-----------|------|
| Workers Requests | 100,000/day | $0.50/million |
| Workers AI (Llama 3) | 10,000 neurons/day | $0.011/1000 neurons |
| Durable Objects | 1M reads/writes | $0.20/million |

**Estimated cost per task**: $0.001 - $0.003

## Troubleshooting

### Issue: "AI binding not found"
**Solution**: Make sure you have `[ai]` binding in `wrangler.toml`

### Issue: "Durable Object not found"
**Solution**: Run migration: `wrangler migrations apply`

### Issue: "Worker timeout"
**Solution**: Complex tasks may exceed 30s CPU limit. Break into smaller tasks.

### Issue: "Rate limit exceeded"
**Solution**: You've hit Workers AI free tier limit. Upgrade or wait for reset.

### Issue: "No response from AI model"
**Solution**: Check `wrangler tail` logs. The model name might have changed. Update `this.model` in `src/durable_object.js`

## Testing

### Manual Testing

1. **Simple Task**: "Create a Hello World function"
2. **Medium Task**: "Build a REST API endpoint"
3. **Complex Task**: "Implement JWT authentication system"

### Automated Testing

```javascript
// test.js
const BASE_URL = 'http://localhost:8787';

async function testWorkflow() {
  const response = await fetch(`${BASE_URL}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      input: 'Create a simple calculator function'
    })
  });

  const data = await response.json();
  console.assert(data.response, 'Response received');
  console.assert(data.agent_invocations.length === 5, '5 agents invoked');
  console.log('Test passed');
}

testWorkflow();
```

## Adapting This Project

### From Python Implementation

If you're coming from the original Python version, here's what changed:

**1. LLM Provider**
- **Before**: OpenAI GPT-4o / Anthropic Claude
- **After**: Cloudflare Workers AI (Llama 3 8B)
- **File**: `src/durable_object.js` - Change `this.model` value

**2. Orchestration**
- **Before**: LangGraph with StateGraph
- **After**: Custom JavaScript async functions
- **File**: `src/durable_object.js` - `executeWorkflow()` method

**3. Deployment**
- **Before**: FastAPI server on VM/container
- **After**: `npx wrangler deploy`
- **File**: `wrangler.toml` for configuration

**4. Session Storage**
- **Before**: In-memory Python dict
- **After**: Durable Objects with persistent storage
- **File**: `src/durable_object.js` - `handleChat()` method

### To Your Own Project

**Step 1: Copy Core Files**
```bash
cp src/durable_object.js your-project/src/
cp src/worker.js your-project/src/
cp wrangler.toml your-project/
```

**Step 2: Customize Agent Prompts**

Edit `src/durable_object.js`, find `getAgentPrompt()` method:

```javascript
getAgentPrompt(agentType, context) {
  const prompts = {
    research: `Your custom research prompt...`,
    developer: `Your custom developer prompt...`,
    // ... customize all 5 agents
  };
  return prompts[agentType] || "";
}
```

**Step 3: Adjust Configuration**

In `wrangler.toml`:
```toml
name = "your-project-name"  # Change this
main = "src/worker.js"
compatibility_date = "2024-01-01"
```

**Step 4: Customize UI**

Edit the `getHTML()` function in `src/worker.js`:
- Change colors in `<style>` section
- Update header text
- Modify welcome message

**Step 5: Deploy**
```bash
wrangler login
npx wrangler deploy
```

## Additional Resources

- **PROMPTS.md**: Detailed documentation of all AI prompts used
- **DEPLOYMENT.md**: Complete deployment guide with troubleshooting
- **SUBMISSION_CHECKLIST.md**: Cloudflare submission checklist
- **Cloudflare Workers Docs**: https://developers.cloudflare.com/workers/
- **Workers AI Docs**: https://developers.cloudflare.com/workers-ai/

## Contributing

Contributions welcome! Areas for improvement:

- Add streaming responses for real-time feedback
- Implement agent parallelization where possible
- Add file generation/output capabilities
- Create more specialized agents (e.g., Security Agent, Performance Agent)
- Build advanced UI with agent status visualization
- Add support for multiple LLM models

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Based on the original SWE Security Orchestrator Python implementation
- Inspired by n8n multi-agent workflows
- Powered by Cloudflare Workers AI and Llama 3 8B

## Example Tasks to Try

### Beginner
- "Create a function to check if a number is prime"
- "Build a simple TODO list manager class"
- "Write a regex validator for phone numbers"

### Intermediate
- "Create a REST API for user CRUD operations"
- "Implement a binary search tree with insert/delete"
- "Build a rate limiter middleware"

### Advanced
- "Design a distributed caching system"
- "Implement OAuth 2.0 authorization flow"
- "Create a webhook processing system with retry logic"

---

**Ready to deploy?**

```bash
npx wrangler deploy
```

Your SWE orchestrator will be live at `https://your-worker.workers.dev`
