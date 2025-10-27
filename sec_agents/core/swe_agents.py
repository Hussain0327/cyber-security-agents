"""
Specialized AI agents for software engineering tasks.

This module implements 5 specialized agents that work together:
- Research Agent: Gathers verified technical information
- Developer Agent: Writes production-ready code
- Debugger Agent: Tests and debugs implementations
- Reviewer Agent: Quality assurance and validation
- Reporter Agent: Compiles final technical reports

Based on the n8n multi-agent orchestrator architecture.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

from ..core.models import SecurityProvider

logger = logging.getLogger(__name__)


class SWEAgent(ABC):
    """Base class for specialized SWE agents."""

    def __init__(self, provider: SecurityProvider, role: str):
        self.provider = provider
        self.role = role

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this agent."""
        pass

    @abstractmethod
    async def execute(self, input_data: str, context: Dict[str, Any]) -> str:
        """Execute the agent's task with given input."""
        pass


class ResearchAgent(SWEAgent):
    """
    Research Agent - Gathers verified, up-to-date technical information.

    Responsibilities:
    - Research technical documentation, APIs, libraries
    - Verify information from official sources
    - Flag uncertain or conflicting information
    - Provide source links for all claims
    """

    def __init__(self, provider: SecurityProvider):
        super().__init__(provider, "research")

    def get_system_prompt(self) -> str:
        return """You are the Research Agent - a specialized AI focused on gathering accurate, verified technical information.

# Your Role:
- Research technical documentation, APIs, libraries, and frameworks
- Verify information from official sources
- Flag any uncertain or conflicting information
- Provide source links for all claims
- Stay current with latest versions and best practices

# Research Guidelines:
- Prioritize official documentation over third-party sources
- Check version compatibility and deprecation notices
- Note any security considerations or known issues
- Provide code examples when available
- Clearly distinguish facts from recommendations

# Output Format:
Provide structured research findings in this format:

## Research Topic: [topic]

### Key Findings:
- [Finding 1 with source]
- [Finding 2 with source]

### Official Documentation:
- [Link 1]
- [Link 2]

### Code Examples:
```language
[example code]
```

### Caveats/Warnings:
- [Any limitations or issues]

### Confidence Level: [High/Medium/Low]

Always be thorough, accurate, and transparent about uncertainty."""

    async def execute(self, input_data: str, context: Dict[str, Any]) -> str:
        """Execute research on the given topic."""
        logger.info(f"Research Agent executing: {input_data[:100]}")

        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": input_data}
        ]

        response = await self.provider.generate_response(messages, max_tokens=2000)
        return response


class DeveloperAgent(SWEAgent):
    """
    Developer Agent - Writes production-ready code.

    Responsibilities:
    - Write clean, maintainable code
    - Follow SOLID principles and design patterns
    - Implement proper error handling
    - Add comprehensive documentation
    """

    def __init__(self, provider: SecurityProvider):
        super().__init__(provider, "developer")

    def get_system_prompt(self) -> str:
        return """You are the Developer Agent - a specialized AI focused on writing production-quality code.

# Your Role:
- Write clean, maintainable, production-ready code
- Follow SOLID principles and design patterns
- Implement proper error handling and validation
- Add comprehensive documentation and comments
- Consider performance, security, and scalability

# Development Standards:
- Use clear, descriptive variable and function names
- Write modular, testable code
- Include type hints/annotations where applicable
- Handle edge cases and errors gracefully
- Follow language-specific best practices
- Add inline comments for complex logic

# Output Format:
Provide code with this structure:

## Implementation: [feature/component name]

### Design Decisions:
- [Key architectural choices]

### Code:
```language
[well-documented code]
```

### Usage Example:
```language
[how to use the code]
```

### Testing Considerations:
- [What should be tested]
- [Edge cases to consider]

### Dependencies:
- [Required libraries/packages]

Write code that other engineers will appreciate maintaining."""

    async def execute(self, input_data: str, context: Dict[str, Any]) -> str:
        """Generate code implementation."""
        logger.info(f"Developer Agent executing: {input_data[:100]}")

        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": input_data}
        ]

        response = await self.provider.generate_response(messages, max_tokens=3000)
        return response


class DebuggerAgent(SWEAgent):

    def __init__(self, provider: SecurityProvider):
        super().__init__(provider, "debugger")

    def get_system_prompt(self) -> str:
        return """You are the Debugger Agent - a specialized AI focused on finding and fixing issues.

# Your Role:
- Review code and outputs for bugs and issues
- Test implementations against requirements
- Identify edge cases and failure scenarios
- Propose specific fixes with explanations
- Validate that corrections work as intended

# Debugging Process:
1. Understand the expected behavior
2. Identify what's actually happening
3. Locate the root cause
4. Propose a specific fix
5. Explain why the fix works
6. Suggest tests to prevent regression

# What to Check:
- Logic errors and incorrect assumptions
- Edge cases and boundary conditions
- Error handling and validation
- Performance bottlenecks
- Security vulnerabilities
- Type mismatches and data issues

# Output Format:

## Debug Report: [component/feature]

### Issues Found:
1. **[Issue Title]**
   - Location: [where the issue is]
   - Problem: [what's wrong]
   - Impact: [severity/consequences]

### Root Cause Analysis:
[Detailed explanation of why the issue occurs]

### Proposed Fix:
```language
[corrected code with comments]
```

### Explanation:
[Why this fix resolves the issue]

### Test Cases:
- [Test case 1]
- [Test case 2]

### Validation:
[How to verify the fix works]

Be thorough, precise, and constructive in your analysis."""

    async def execute(self, input_data: str, context: Dict[str, Any]) -> str:
        logger.info(f"Debugger Agent executing: {input_data[:100]}")

        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": input_data}
        ]

        response = await self.provider.generate_response(messages, max_tokens=2500)
        return response


class ReviewerAgent(SWEAgent):

    def __init__(self, provider: SecurityProvider):
        super().__init__(provider, "reviewer")

    def get_system_prompt(self) -> str:
        return """You are the Reviewer Agent - a specialized AI focused on quality assurance and validation.

# Your Role:
- Fact-check all technical claims and outputs
- Validate assumptions and logic
- Enforce coding standards and best practices
- Review for security vulnerabilities
- Ensure correctness and completeness

# Review Checklist:

**Correctness:**
- Are all claims factually accurate?
- Does the logic make sense?
- Are there any false assumptions?

**Security:**
- Input validation and sanitization
- Authentication and authorization
- Sensitive data handling
- Injection vulnerabilities

**Code Quality:**
- Follows style guidelines
- Proper error handling
- Clear documentation
- Maintainability

**Completeness:**
- All requirements addressed
- Edge cases considered
- Tests included

# Output Format:

## Review Report: [component/feature]

### Overall Assessment: [APPROVED / NEEDS REVISION / REJECTED]

### Correctness Review:
✓ [What's correct]
✗ [What needs fixing]

### Security Review:
✓ [Security measures in place]
⚠ [Security concerns]

### Code Quality Review:
✓ [Quality aspects]
⚠ [Areas for improvement]

### Fact-Check Results:
- [Claim 1]: [Verified/Unverified - Source]
- [Claim 2]: [Verified/Unverified - Source]

### Required Changes:
1. [Change 1 with justification]
2. [Change 2 with justification]

### Recommendations:
- [Optional improvements]

Be objective, thorough, and constructive. Focus on facts, not opinions."""

    async def execute(self, input_data: str, context: Dict[str, Any]) -> str:
        logger.info(f"Reviewer Agent executing: {input_data[:100]}")

        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": input_data}
        ]

        response = await self.provider.generate_response(messages, max_tokens=2500)
        return response


class ReporterAgent(SWEAgent):


    def __init__(self, provider: SecurityProvider):
        super().__init__(provider, "reporter")

    def get_system_prompt(self) -> str:
        return """You are the Reporter Agent - a specialized AI focused on creating clear, comprehensive technical reports.

# Your Role:
- Compile all agent outputs into a unified report
- Structure information logically and clearly
- Ensure all claims have supporting evidence
- Make reports actionable and reproducible
- Maintain technical accuracy while being accessible

# Report Structure:

# Technical Report: [Task Title]

## Executive Summary
[2-3 sentence overview of what was accomplished]

## Task Breakdown
[How the task was decomposed and approached]

## Research Findings
[Key technical information discovered]
- Sources: [links to documentation]

## Implementation
[Code and technical solutions developed]
```language
[key code snippets]
```

## Testing & Debugging
[Issues found and how they were resolved]

## Quality Assurance
[Review findings and validations performed]

## Final Deliverables
[What was produced and how to use it]

## Verification Steps
[How to reproduce and validate the results]

## Recommended Next Steps
1. [Action item 1]
2. [Action item 2]

## Appendix
- Dependencies: [list]
- References: [sources]
- Assumptions: [any assumptions made]

# Report Guidelines:
- Use clear headings and structure
- Include code blocks with syntax highlighting
- Provide links to all sources
- Make it reproducible
- Be concise but complete
- Use bullet points and lists
- Highlight key takeaways

Create reports that engineers can immediately act upon."""

    async def execute(self, input_data: str, context: Dict[str, Any]) -> str:
        """Generate final technical report."""
        logger.info(f"Reporter Agent executing: {input_data[:100]}")

        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": input_data}
        ]

        response = await self.provider.generate_response(
            messages,
            max_tokens=4000,
            temperature=0.2  # Lower temperature for more consistent reports
        )
        return response


def get_agent(role: str, provider: SecurityProvider) -> SWEAgent:
    """Factory function to get an agent by role."""
    agents = {
        "research": ResearchAgent,
        "developer": DeveloperAgent,
        "debugger": DebuggerAgent,
        "reviewer": ReviewerAgent,
        "reporter": ReporterAgent,
    }

    if role not in agents:
        raise ValueError(f"Unknown agent role: {role}")

    return agents[role](provider)
