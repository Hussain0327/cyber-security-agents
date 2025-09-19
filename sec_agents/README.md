# Security Agents 🛡️

An AI-powered cybersecurity analysis and response framework built with LangGraph, FastAPI, and modern security tools.

## Features

- **Multi-Provider AI Support**: OpenAI, Anthropic, and local LLM integration
- **Advanced Security Analysis**: Log triage, incident response, threat hunting, and malware analysis
- **MITRE ATT&CK Integration**: Automatic technique mapping and attack chain analysis
- **Sigma Rule Generation**: Automated detection rule creation from security findings
- **Scenario-Based Testing**: Comprehensive evaluation framework with golden datasets
- **RESTful API**: FastAPI-based service with authentication and tracing
- **CLI Interface**: Powerful command-line tool for security operations
- **Interactive Notebooks**: Jupyter notebooks for exploration and demonstration

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd sec-agents

# Install dependencies
pip install -e .

# Set up environment variables (optional)
export OPENAI_API_KEY="your-openai-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
```

### CLI Usage

```bash
# List available scenarios
sec-agents list

# Run a security scenario
sec-agents run log_triage

# Perform ad-hoc analysis
sec-agents analyze log_triage --data '{"raw_log": "suspicious activity"}'

# Start the API server
sec-agents serve --host 0.0.0.0 --port 8000

# Generate authentication token
sec-agents auth

# Run evaluation tests
sec-agents test --scenarios
```

### API Usage

```python
import httpx
from sec_agents.app.auth import generate_demo_token

# Generate token
token = generate_demo_token()

# Make API request
response = httpx.post(
    "http://localhost:8000/analyze",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "analysis_type": "log_triage",
        "data": {"raw_log": "2024-01-15 14:32:15 [INFO] EventID=4688 ProcessName=powershell.exe"}
    }
)
```

### Python Integration

```python
from sec_agents.core.graph import SecurityGraph
from sec_agents.core.models import AnalysisRequest, AnalysisType

# Initialize security graph
graph = SecurityGraph(provider_type="openai")

# Create analysis request
request = AnalysisRequest(
    analysis_type=AnalysisType.LOG_TRIAGE,
    data={"raw_log": "suspicious activity logs"}
)

# Run analysis
result = await graph.analyze(request)
print(f"Threat Level: {result.threat_level}")
print(f"MITRE Techniques: {result.mitre_techniques}")
```

## Architecture

```
sec-agents/
├── app/                  # FastAPI application
│   ├── main.py          # API endpoints and server setup
│   ├── auth.py          # Authentication and authorization
│   └── tracing.py       # Request tracing and logging
├── core/                # Core analysis engine
│   ├── graph.py         # LangGraph state machine
│   └── models.py        # Data models and AI providers
├── tools/               # Security analysis tools
│   ├── parsers.py       # Data parsing (logs, network, files)
│   ├── sigma_builder.py # Sigma rule generation
│   └── mitre_mapper.py  # MITRE ATT&CK mapping
├── scenarios/           # Pre-defined analysis scenarios
│   ├── log_triage.yaml
│   ├── incident_response.yaml
│   └── threat_hunting.yaml
├── data/                # Sample data and threat intelligence
├── evals/               # Evaluation framework and tests
├── notebooks/           # Jupyter notebooks for demos
└── cli.py              # Command-line interface
```

## Analysis Types

### Log Triage
Analyze security logs for suspicious activities, failed authentications, and anomalous behavior patterns.

### Incident Response
Comprehensive analysis for security incidents including initial compromise, lateral movement, and impact assessment.

### Threat Hunting
Advanced persistent threat detection using behavioral analysis and living-off-the-land technique identification.

### Malware Analysis
File and binary analysis for malicious indicators, behavioral patterns, and threat classification.

### Vulnerability Assessment
Security weakness identification and risk assessment with remediation recommendations.

## Security Tools Integration

### MITRE ATT&CK Framework
- Automatic technique mapping from security findings
- Attack chain reconstruction and analysis
- Tactic coverage assessment and gap analysis
- Risk scoring based on technique severity

### Sigma Rules
- Automated detection rule generation
- Rule validation and optimization
- Support for multiple log sources and platforms
- False positive reduction techniques

### Threat Intelligence
- IOC enrichment and correlation
- Campaign attribution and tracking
- Behavioral pattern recognition
- Risk assessment and prioritization

## Evaluation Framework

The framework includes comprehensive evaluation capabilities:

```bash
# Run all tests
sec-agents test

# Run specific test categories
sec-agents test --scenarios --integration

# Performance benchmarking
python -m pytest evals/ -k "performance" -v
```

### Golden Dataset
- Predefined expected outputs for scenario validation
- Confidence score and threat level consistency checks
- MITRE technique mapping accuracy verification
- Performance threshold monitoring

## Development

### Adding New Scenarios

1. Create a YAML file in `scenarios/`:
```yaml
name: "Custom Security Scenario"
description: "Description of the scenario"
steps:
  - name: "analysis_step"
    analysis_type: "log_triage"
    input_data: { ... }
    expected_output: { ... }
```

2. Add corresponding test cases in `evals/`

### Extending AI Providers

```python
from sec_agents.core.models import SecurityProvider

class CustomProvider(SecurityProvider):
    async def analyze_security_data(self, data, analysis_type):
        # Implement custom analysis logic
        return AnalysisResult(...)
```

### Custom Security Tools

```python
from sec_agents.tools.parsers import LogParser

class CustomParser(LogParser):
    async def parse(self, data):
        # Implement custom parsing logic
        return parsed_data
```

## Configuration

Environment variables:
- `OPENAI_API_KEY`: OpenAI API key for GPT models
- `ANTHROPIC_API_KEY`: Anthropic API key for Claude models
- `JWT_SECRET_KEY`: JWT secret for API authentication
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Performance

Typical performance metrics:
- Log parsing: ~0.01s per batch
- MITRE mapping: ~0.02s per finding
- Sigma rule generation: ~0.05s per rule
- Full scenario analysis: ~5-15s depending on complexity

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run tests: `sec-agents test`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions and support:
- Create an issue on GitHub
- Check the documentation in `notebooks/demo.ipynb`
- Review example scenarios in the `scenarios/` directory

## Roadmap

- [ ] Real-time stream processing
- [ ] Additional AI provider integrations
- [ ] Enhanced visualization dashboard
- [ ] Kubernetes deployment templates
- [ ] SOAR platform integrations
- [ ] Custom model fine-tuning capabilities