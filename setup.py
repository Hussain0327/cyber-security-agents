from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="cybersecurity-agents",
    version="0.2.0",
    description="AI-powered cybersecurity analysis and SWE multi-agent orchestrator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Raja Hussain",
    author_email="rajahh7865@example.com",
    url="https://github.com/yourusername/cybersecurity-agents",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        # Core
        "python-dotenv>=1.0.0",

        # LangGraph and LangChain
        "langgraph>=0.2.34",
        "langchain-core>=0.3.10",
        "langchain>=0.3.4",
        "langchain-openai>=0.2.1",
        "langchain-anthropic>=0.2.1",

        # LLM Providers
        "openai>=1.51.0",
        "anthropic>=0.39.0",

        # Web Framework
        "fastapi>=0.115.0",
        "uvicorn>=0.31.0",
        "httpx>=0.27.2",

        # Data Validation
        "pydantic>=2.9.2",
        "pydantic-settings>=2.5.2",

        # CLI
        "click>=8.1.7",
        "rich>=13.8.1",

        # Security
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",

        # Utilities
        "pyyaml>=6.0.2",
    ],
    extras_require={
        "dev": [
            "pytest>=8.3.3",
            "pytest-asyncio>=0.24.0",
            "pytest-cov>=5.0.0",
            "black>=24.8.0",
            "ruff>=0.6.8",
            "mypy>=1.11.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "sec-agents=sec_agents.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="cybersecurity ai agents langchain langgraph openai anthropic security",
)
