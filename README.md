# 🤖 SWE Security Orchestrator

A multi-agent AI system for software engineering tasks, powered by **Cloudflare Workers AI** and **Llama 3.1 70B Instruct**. This orchestrator coordinates 5 specialized agents to complete end-to-end development workflows with research, implementation, debugging, review, and reporting.

## 🌟 Features

- **5 Specialized AI Agents**: Research, Developer, Debugger, Reviewer, Reporter
- **Cloudflare Workers AI**: Runs on Llama 3.1 70B Instruct model
- **Durable Objects**: Stateful conversation management with session persistence
- **Built-in Web UI**: Simple chat interface for interacting with agents
- **Production-Ready**: Deployed on Cloudflare's global edge network
- **Cost-Effective**: Pay-per-use pricing with Workers AI

## 🏗️ Architecture

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

## 📁 Project Structure

```
cf_ai_swe_security_orchestrator/
├── src/
│   ├── worker.js           # Main Worker (entry point)
│   ├── durable_object.js   # Multi-agent orchestrator
│   └── ui/                 # (Future: separate UI assets)
├── README.md               # This file
├── PROMPTS.md              # All AI prompts used
└── wrangler.toml           # Cloudflare configuration
```

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ installed
- Cloudflare account (free tier works)
- Wrangler CLI installed

### 1. Install Wrangler

```bash
npm install -g wrangler
```

### 2. Authenticate with Cloudflare

```bash
wrangler login
```

### 3. Clone/Navigate to Project

```bash
cd cf_ai_swe_security_orchestrator
```

### 4. Deploy to Cloudflare

```bash
npx wrangler deploy
```

That's it! Your orchestrator is now live on Cloudflare's edge network.

## 🔧 Development

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

### View Logs

```bash
wrangler tail
```

## 📡 API Endpoints

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
    ...
  ],
  "execution_time_ms": 18456
}
```

## 🎯 Usage Examples

### Web UI

1. Deploy your Worker: `npx wrangler deploy`
2. Open the URL provided (e.g., `https://your-worker.workers.dev`)
3. Type your request in the chat box
4. Watch the 5 agents work in sequence!

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

## 🧠 Agent Capabilities

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
- Considers scalability & security

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

## ⚙️ Configuration

### wrangler.toml

Key settings in your `wrangler.toml`:

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
new_classes = ["SWEOrchestrator"]
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

## 📊 Performance

| Metric | Value |
|--------|-------|
| Average Workflow Time | 17-32 seconds |
| Agent Invocations | 5 per task |
| Token Usage | ~5000-12000 per task |
| Cold Start | <1 second |
| Geographic Latency | <100ms (edge) |

**Optimization Tips:**
- Use session IDs to maintain context
- Keep tasks focused and specific
- Break complex projects into subtasks

## 🔒 Security Considerations

### Current Implementation
- ✅ CORS enabled for browser access
- ✅ Session isolation via Durable Objects
- ✅ No authentication required (demo mode)

### Production Recommendations
- 🔐 Add API key authentication
- 🔐 Implement rate limiting
- 🔐 Add request validation
- 🔐 Enable Cloudflare Access for UI
- 🔐 Monitor usage with Analytics

**Example: Add API Key Auth**
```javascript
if (request.headers.get('Authorization') !== `Bearer ${env.API_KEY}`) {
  return new Response('Unauthorized', { status: 401 });
}
```

## 💰 Cost Estimation

Cloudflare Workers AI pricing (as of 2024):

| Component | Free Tier | Paid |
|-----------|-----------|------|
| Workers Requests | 100,000/day | $0.50/million |
| Workers AI (Llama 3.1) | 10,000 neurons/day | $0.011/1000 neurons |
| Durable Objects | 1M reads/writes | $0.20/million |

**Estimated cost per task**: $0.001 - $0.003

## 🛠️ Troubleshooting

### Issue: "AI binding not found"
**Solution**: Make sure you have `[ai]` binding in `wrangler.toml`

### Issue: "Durable Object not found"
**Solution**: Run migration: `wrangler migrations apply`

### Issue: "Worker timeout"
**Solution**: Complex tasks may exceed 30s CPU limit. Break into smaller tasks.

### Issue: "Rate limit exceeded"
**Solution**: You've hit Workers AI free tier limit. Upgrade or wait for reset.

## 🧪 Testing

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
  console.log('✅ Test passed');
}

testWorkflow();
```

## 📚 Additional Resources

- **PROMPTS.md**: Detailed documentation of all AI prompts used
- **Cloudflare Workers Docs**: https://developers.cloudflare.com/workers/
- **Workers AI Docs**: https://developers.cloudflare.com/workers-ai/
- **Llama 3.1 Model Card**: https://ai.meta.com/llama/

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- [ ] Add streaming responses for real-time feedback
- [ ] Implement agent parallelization where possible
- [ ] Add file generation/output capabilities
- [ ] Create more specialized agents (e.g., Security Agent, Performance Agent)
- [ ] Build advanced UI with agent status visualization
- [ ] Add support for multiple LLM models

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- Based on the original [SWE Security Orchestrator](../README.md) Python implementation
- Inspired by n8n multi-agent workflows
- Powered by Cloudflare Workers AI and Llama 3.1

---

## 🎓 Example Tasks to Try

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

**Ready to build?** Deploy now:

```bash
npx wrangler deploy
```

Your SWE orchestrator will be live at `https://your-worker.workers.dev` 🚀
