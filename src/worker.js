/**
 * SWE Security Orchestrator - Main Worker
 *
 * Entry point for the Cloudflare Workers AI-powered
 * multi-agent software engineering system.
 *
 * Routes requests to Durable Objects for stateful conversation management.
 */

import { SWEOrchestrator } from './durable_object.js';

export { SWEOrchestrator };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS headers for browser access
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Route: Health check
      if (url.pathname === '/health') {
        return new Response(JSON.stringify({
          status: 'healthy',
          service: 'SWE Security Orchestrator',
          version: '1.0.0',
          model: '@cf/meta/llama-3.3-70b-instruct'
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Route: Serve UI
      if (url.pathname === '/' || url.pathname === '/index.html') {
        return new Response(getHTML(), {
          headers: { ...corsHeaders, 'Content-Type': 'text/html' }
        });
      }

      // All other routes go to the Durable Object
      // Get or create a session ID
      const sessionId = url.searchParams.get('session_id') || 'default';

      // Get Durable Object ID
      const id = env.SWE_ORCHESTRATOR.idFromName(sessionId);

      // Get Durable Object stub
      const stub = env.SWE_ORCHESTRATOR.get(id);

      // Forward request to Durable Object
      const response = await stub.fetch(request);

      // Add CORS headers to response
      const newResponse = new Response(response.body, response);
      Object.entries(corsHeaders).forEach(([key, value]) => {
        newResponse.headers.set(key, value);
      });

      return newResponse;

    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        details: error.message
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  },
};

/**
 * Simple embedded HTML UI
 */
function getHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SWE Security Orchestrator</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }

    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      width: 100%;
      max-width: 900px;
      height: 700px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 24px;
      text-align: center;
    }

    .header h1 {
      font-size: 24px;
      margin-bottom: 8px;
    }

    .header p {
      font-size: 14px;
      opacity: 0.9;
    }

    .chat-box {
      flex: 1;
      padding: 20px;
      overflow-y: auto;
      background: #f7f9fc;
    }

    .message {
      margin-bottom: 16px;
      animation: slideIn 0.3s ease;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .message.user {
      text-align: right;
    }

    .message-content {
      display: inline-block;
      padding: 12px 16px;
      border-radius: 12px;
      max-width: 80%;
      word-wrap: break-word;
    }

    .message.user .message-content {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }

    .message.assistant .message-content {
      background: white;
      color: #333;
      border: 1px solid #e0e0e0;
      text-align: left;
    }

    .message.system {
      text-align: center;
    }

    .message.system .message-content {
      background: #e3f2fd;
      color: #1976d2;
      font-size: 12px;
      padding: 8px 12px;
    }

    .input-area {
      padding: 20px;
      background: white;
      border-top: 1px solid #e0e0e0;
    }

    .input-container {
      display: flex;
      gap: 12px;
    }

    #userInput {
      flex: 1;
      padding: 12px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 24px;
      font-size: 14px;
      outline: none;
      transition: border-color 0.3s;
    }

    #userInput:focus {
      border-color: #667eea;
    }

    #sendBtn {
      padding: 12px 32px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 24px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }

    #sendBtn:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }

    #sendBtn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .loading {
      display: inline-block;
      width: 12px;
      height: 12px;
      border: 2px solid #f3f3f3;
      border-top: 2px solid #667eea;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    .stats {
      margin-top: 8px;
      font-size: 11px;
      color: #666;
    }

    pre {
      background: #f5f5f5;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
      margin: 8px 0;
    }

    code {
      font-family: 'Courier New', monospace;
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🤖 SWE Security Orchestrator</h1>
      <p>Multi-Agent AI powered by Cloudflare Workers & Llama 3.3</p>
    </div>

    <div class="chat-box" id="chatBox">
      <div class="message system">
        <div class="message-content">
          <strong>Welcome!</strong> This orchestrator coordinates 5 specialized AI agents:<br>
          Research → Developer → Debugger → Reviewer → Reporter
        </div>
      </div>
    </div>

    <div class="input-area">
      <div class="input-container">
        <input
          type="text"
          id="userInput"
          placeholder="Ask me to build something... (e.g., 'Create a REST API for user management')"
          onkeypress="if(event.key==='Enter') sendMessage()"
        />
        <button id="sendBtn" onclick="sendMessage()">Send</button>
      </div>
    </div>
  </div>

  <script>
    const chatBox = document.getElementById('chatBox');
    const userInput = document.getElementById('userInput');
    const sendBtn = document.getElementById('sendBtn');

    async function sendMessage() {
      const input = userInput.value.trim();
      if (!input) return;

      // Disable input
      userInput.disabled = true;
      sendBtn.disabled = true;
      sendBtn.innerHTML = '<span class="loading"></span>';

      // Add user message
      addMessage('user', input);
      userInput.value = '';

      try {
        // Send to API
        const response = await fetch('/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input })
        });

        const data = await response.json();

        if (data.error) {
          addMessage('system', '❌ Error: ' + data.error);
        } else {
          // Add assistant response
          addMessage('assistant', data.response);

          // Show stats
          if (data.agent_invocations && data.execution_time_ms) {
            const stats = \`⏱️ Completed in \${(data.execution_time_ms / 1000).toFixed(1)}s | 🤖 \${data.agent_invocations.length} agents invoked\`;
            addMessage('system', stats);
          }
        }
      } catch (error) {
        addMessage('system', '❌ Network error: ' + error.message);
      }

      // Re-enable input
      userInput.disabled = false;
      sendBtn.disabled = false;
      sendBtn.textContent = 'Send';
      userInput.focus();
    }

    function addMessage(type, content) {
      const messageDiv = document.createElement('div');
      messageDiv.className = \`message \${type}\`;

      const contentDiv = document.createElement('div');
      contentDiv.className = 'message-content';

      // Basic markdown-like formatting
      const formatted = content
        .replace(/\`\`\`(\\w+)?\\n([\\s\\S]*?)\`\`\`/g, '<pre><code>$2</code></pre>')
        .replace(/\`([^\`]+)\`/g, '<code>$1</code>')
        .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
        .replace(/\\n/g, '<br>');

      contentDiv.innerHTML = formatted;
      messageDiv.appendChild(contentDiv);
      chatBox.appendChild(messageDiv);

      // Scroll to bottom
      chatBox.scrollTop = chatBox.scrollHeight;
    }

    // Focus input on load
    userInput.focus();
  </script>
</body>
</html>`;
}
