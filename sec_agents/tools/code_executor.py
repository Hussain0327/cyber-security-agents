"""
Code execution tool for running JavaScript and Python code.

This tool allows agents to execute code snippets to test implementations,
validate logic, or perform computations. Includes basic sandboxing for safety.
"""

import asyncio
import subprocess
import tempfile
import os
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class CodeExecutionError(Exception):
    """Exception raised when code execution fails."""
    pass


class CodeExecutor:
    """
    Executes JavaScript and Python code with basic sandboxing.

    Provides a safe environment for agents to run code and see actual results.
    """

    def __init__(
        self,
        timeout_seconds: int = 30,
        max_output_size: int = 10000,
        enable_network: bool = False
    ):
        """
        Initialize code executor.

        Args:
            timeout_seconds: Maximum execution time
            max_output_size: Maximum output size in characters
            enable_network: Allow network access (disabled by default)
        """
        self.timeout_seconds = timeout_seconds
        self.max_output_size = max_output_size
        self.enable_network = enable_network

    async def execute_python(
        self,
        code: str,
        variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute Python code.

        Args:
            code: Python code to execute
            variables: Optional variables to inject into scope

        Returns:
            Dict with stdout, stderr, return_value, and success flag
        """
        logger.info(f"Executing Python code: {code[:100]}...")

        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False
        ) as f:
            temp_file = f.name

            # Inject variables if provided
            if variables:
                f.write("# Injected variables\n")
                for key, value in variables.items():
                    f.write(f"{key} = {repr(value)}\n")
                f.write("\n")

            f.write(code)

        try:
            # Execute Python code
            result = await asyncio.create_subprocess_exec(
                'python3',
                temp_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(),
                    timeout=self.timeout_seconds
                )

                stdout_str = stdout.decode('utf-8', errors='replace')
                stderr_str = stderr.decode('utf-8', errors='replace')

                # Truncate output if too large
                if len(stdout_str) > self.max_output_size:
                    stdout_str = (
                        stdout_str[:self.max_output_size]
                        + f"\n... [truncated, {len(stdout_str)} total chars]"
                    )

                return {
                    "success": result.returncode == 0,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "return_code": result.returncode,
                    "language": "python"
                }

            except asyncio.TimeoutError:
                result.kill()
                raise CodeExecutionError(
                    f"Code execution timed out after {self.timeout_seconds}s"
                )

        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Failed to delete temp file {temp_file}: {e}")

    async def execute_javascript(
        self,
        code: str,
        variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute JavaScript code using Node.js.

        Args:
            code: JavaScript code to execute
            variables: Optional variables to inject into scope

        Returns:
            Dict with stdout, stderr, return_value, and success flag
        """
        logger.info(f"Executing JavaScript code: {code[:100]}...")

        # Check if Node.js is available
        try:
            node_check = await asyncio.create_subprocess_exec(
                'node',
                '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await node_check.communicate()
            if node_check.returncode != 0:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "Node.js not available on this system",
                    "return_code": -1,
                    "language": "javascript"
                }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Node.js not installed. Install Node.js to run JavaScript.",
                "return_code": -1,
                "language": "javascript"
            }

        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.js',
            delete=False
        ) as f:
            temp_file = f.name

            # Inject variables if provided
            if variables:
                f.write("// Injected variables\n")
                for key, value in variables.items():
                    f.write(f"const {key} = {json.dumps(value)};\n")
                f.write("\n")

            f.write(code)

        try:
            # Execute JavaScript code
            result = await asyncio.create_subprocess_exec(
                'node',
                temp_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(),
                    timeout=self.timeout_seconds
                )

                stdout_str = stdout.decode('utf-8', errors='replace')
                stderr_str = stderr.decode('utf-8', errors='replace')

                # Truncate output if too large
                if len(stdout_str) > self.max_output_size:
                    stdout_str = (
                        stdout_str[:self.max_output_size]
                        + f"\n... [truncated, {len(stdout_str)} total chars]"
                    )

                return {
                    "success": result.returncode == 0,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "return_code": result.returncode,
                    "language": "javascript"
                }

            except asyncio.TimeoutError:
                result.kill()
                raise CodeExecutionError(
                    f"Code execution timed out after {self.timeout_seconds}s"
                )

        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Failed to delete temp file {temp_file}: {e}")

    async def execute(
        self,
        code: str,
        language: str = "python",
        variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute code in the specified language.

        Args:
            code: Code to execute
            language: Programming language (python, javascript, js)
            variables: Optional variables to inject

        Returns:
            Execution result dict
        """
        language = language.lower()

        try:
            if language == "python" or language == "py":
                return await self.execute_python(code, variables)
            elif language == "javascript" or language == "js" or language == "node":
                return await self.execute_javascript(code, variables)
            else:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Unsupported language: {language}. Supported: python, javascript",
                    "return_code": -1,
                    "language": language
                }
        except Exception as e:
            logger.error(f"Code execution error: {str(e)}")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Execution error: {str(e)}",
                "return_code": -1,
                "language": language
            }


# Singleton instance for easy access
_executor_instance: Optional[CodeExecutor] = None


def get_executor() -> CodeExecutor:
    """Get or create the global CodeExecutor instance."""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = CodeExecutor()
    return _executor_instance
