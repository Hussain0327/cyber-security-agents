export class SWEOrchestrator {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    // Using Llama 3 8B Instruct - verified available on Workers AI
    this.model = "@cf/meta/llama-3-8b-instruct";
  }

  async fetch(request) {
    const url = new URL(request.url);

    // Handle different endpoints
    if (url.pathname === "/chat" && request.method === "POST") {
      return this.handleChat(request);
    } else if (url.pathname === "/history" && request.method === "GET") {
      return this.getHistory();
    } else if (url.pathname === "/clear" && request.method === "POST") {
      return this.clearHistory();
    }

    return new Response("Not Found", { status: 404 });
  }

  async handleChat(request) {
    try {
      const body = await request.json();
      const userInput = body.input;

      if (!userInput) {
        return Response.json({ error: "Input is required" }, { status: 400 });
      }

      // Get conversation history
      const history = (await this.state.storage.get("history")) || [];

      // Add user message
      history.push({ role: "user", content: userInput });

      // Execute the 5-agent workflow
      const workflowResult = await this.executeWorkflow(userInput, history);

      // Add assistant response
      history.push({
        role: "assistant",
        content: workflowResult.report
      });

      // Keep only last 20 messages (rolling window like n8n)
      const trimmedHistory = history.slice(-20);
      await this.state.storage.put("history", trimmedHistory);

      return Response.json({
        response: workflowResult.report,
        agent_invocations: workflowResult.invocations,
        execution_time_ms: workflowResult.execution_time_ms
      });

    } catch (error) {
      console.error("Chat error:", error);
      return Response.json({
        error: "Failed to process request",
        details: error.message
      }, { status: 500 });
    }
  }

  async getHistory() {
    const history = (await this.state.storage.get("history")) || [];
    return Response.json({ history });
  }

  async clearHistory() {
    await this.state.storage.put("history", []);
    return Response.json({ message: "History cleared" });
  }

   
  async executeWorkflow(task, history) {
    const startTime = Date.now();
    const invocations = [];

    try {
      // Step 1: Research Agent
      console.log("Executing Research Agent...");
      const researchStart = Date.now();
      const researchFindings = await this.runAgent("research", task, history);
      invocations.push({
        agent: "research",
        execution_time_ms: Date.now() - researchStart,
        output_length: researchFindings.length
      });

      // Step 2: Developer Agent
      console.log("Executing Developer Agent...");
      const devStart = Date.now();
      const codeImplementation = await this.runAgent(
        "developer",
        task,
        history,
        { research_findings: researchFindings }
      );
      invocations.push({
        agent: "developer",
        execution_time_ms: Date.now() - devStart,
        output_length: codeImplementation.length
      });

      // Step 3: Debugger Agent
      console.log("Executing Debugger Agent...");
      const debugStart = Date.now();
      const debugReport = await this.runAgent(
        "debugger",
        task,
        history,
        {
          research_findings: researchFindings,
          code_implementation: codeImplementation
        }
      );
      invocations.push({
        agent: "debugger",
        execution_time_ms: Date.now() - debugStart,
        output_length: debugReport.length
      });

      // Step 4: Reviewer Agent
      console.log("Executing Reviewer Agent...");
      const reviewStart = Date.now();
      const reviewReport = await this.runAgent(
        "reviewer",
        task,
        history,
        {
          research_findings: researchFindings,
          code_implementation: codeImplementation,
          debug_report: debugReport
        }
      );
      invocations.push({
        agent: "reviewer",
        execution_time_ms: Date.now() - reviewStart,
        output_length: reviewReport.length
      });

      // Step 5: Reporter Agent - Compile everything
      console.log("Executing Reporter Agent...");
      const reportStart = Date.now();
      const finalReport = await this.runAgent(
        "reporter",
        task,
        history,
        {
          research_findings: researchFindings,
          code_implementation: codeImplementation,
          debug_report: debugReport,
          review_report: reviewReport
        }
      );
      invocations.push({
        agent: "reporter",
        execution_time_ms: Date.now() - reportStart,
        output_length: finalReport.length
      });

      return {
        report: finalReport,
        invocations: invocations,
        execution_time_ms: Date.now() - startTime
      };

    } catch (error) {
      console.error("Workflow execution error:", error);
      return {
        report: `# Workflow Failed\n\nError: ${error.message}\n\nPlease try again with a simpler task.`,
        invocations: invocations,
        execution_time_ms: Date.now() - startTime
      };
    }
  }


  async runAgent(agentType, task, history, context = {}) {
    try {
      const systemPrompt = this.getAgentPrompt(agentType, context);

      // Build the prompt for this agent
      let userPrompt = `Task: ${task}\n\n`;

      if (context.research_findings) {
        userPrompt += `Research Findings:\n${context.research_findings.substring(0, 1000)}...\n\n`;
      }
      if (context.code_implementation) {
        userPrompt += `Implementation:\n${context.code_implementation.substring(0, 1500)}...\n\n`;
      }
      if (context.debug_report) {
        userPrompt += `Debug Report:\n${context.debug_report.substring(0, 1000)}...\n\n`;
      }
      if (context.review_report) {
        userPrompt += `Review Report:\n${context.review_report.substring(0, 1000)}...\n\n`;
      }

      // Prepare messages for the AI
      const messages = [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ];

      console.log(`Running ${agentType} agent with model ${this.model}`);

      // Call Workers AI with Llama 3
      const response = await this.env.AI.run(this.model, {
        messages: messages,
        max_tokens: this.getMaxTokens(agentType),
        temperature: this.getTemperature(agentType)
      });

      console.log(`${agentType} response type:`, typeof response);
      console.log(`${agentType} response keys:`, Object.keys(response || {}));

      // Extract response - handle different response formats
      if (typeof response === 'string') {
        return response;
      }

      const result = response.response || response.result || response.output || "";

      if (!result) {
        console.error(`${agentType} agent returned empty response:`, JSON.stringify(response));
        return `${agentType} agent completed but returned no output. Response structure: ${JSON.stringify(response)}`;
      }

      return result;
    } catch (error) {
      console.error(`Error in ${agentType} agent:`, error);
      return `Error in ${agentType} agent: ${error.message}`;
    }
  }

  
  getAgentPrompt(agentType, context) {
    const prompts = {
      research: `You are the Research Agent - a specialized AI focused on gathering accurate, verified technical information.

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
\`\`\`language
[example code]
\`\`\`

### Caveats/Warnings:
- [Any limitations or issues]

### Confidence Level: [High/Medium/Low]

Always be thorough, accurate, and transparent about uncertainty.`,

      developer: `You are the Developer Agent - a specialized AI focused on writing production-quality code.

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
\`\`\`language
[well-documented code]
\`\`\`

### Usage Example:
\`\`\`language
[how to use the code]
\`\`\`

### Testing Considerations:
- [What should be tested]
- [Edge cases to consider]

### Dependencies:
- [Required libraries/packages]

Write code that other engineers will appreciate maintaining.`,

      debugger: `You are the Debugger Agent - a specialized AI focused on finding and fixing issues.

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
\`\`\`language
[corrected code with comments]
\`\`\`

### Explanation:
[Why this fix resolves the issue]

### Test Cases:
- [Test case 1]
- [Test case 2]

### Validation:
[How to verify the fix works]

Be thorough, precise, and constructive in your analysis.`,

      reviewer: `You are the Reviewer Agent - a specialized AI focused on quality assurance and validation.

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

Be objective, thorough, and constructive. Focus on facts, not opinions.`,

      reporter: `You are the Reporter Agent - a specialized AI focused on creating clear, comprehensive technical reports.

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
\`\`\`language
[key code snippets]
\`\`\`

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

Create reports that engineers can immediately act upon.`
    };

    return prompts[agentType] || "";
  }

  /**
   * Get max tokens for each agent
   */
  getMaxTokens(agentType) {
    const limits = {
      research: 2000,
      developer: 3000,
      debugger: 2500,
      reviewer: 2500,
      reporter: 4000
    };
    return limits[agentType] || 2000;
  }

  /**
   * Get temperature for each agent
   */
  getTemperature(agentType) {
    // Reporter needs consistency, others can be creative
    return agentType === "reporter" ? 0.2 : 0.7;
  }
}
