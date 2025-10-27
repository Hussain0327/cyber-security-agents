import asyncio
import sys
import os


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sec_agents.sdk import SWEClient


async def example_basic():
    """Basic example: Single task execution."""
    print("=" * 80)
    print("Example 1: Basic Task Execution")
    print("=" * 80)

    client = SWEClient(provider="openai")

    result = await client.execute(
        "Create a Python function to calculate the factorial of a number"
    )

    print("\n📝 Task:", result.task)
    print("✅ Status:", result.status)
    print(f"⏱️  Time: {result.execution_time_seconds:.2f}s")
    print(f"🤖 Agents: {len(result.agent_invocations)}")
    print("\n" + "=" * 80)
    print("REPORT:")
    print("=" * 80)
    print(result.report)


async def example_session():
    """Session-based example: Multi-step development."""
    print("\n\n" + "=" * 80)
    print("Example 2: Session-Based Multi-Step Development")
    print("=" * 80)

    client = SWEClient(provider="openai", session_id="quickstart-demo")

    
    print("\n🔹 Step 1: Creating base class...")
    result1 = await client.execute(
        "Create a Calculator class with add and subtract methods"
    )
    print(f"   Status: {result1.status} ({result1.execution_time_seconds:.2f}s)")

    
    print("\n🔹 Step 2: Extending functionality...")
    result2 = await client.execute(
        "Add multiply and divide methods to the Calculator"
    )
    print(f"   Status: {result2.status} ({result2.execution_time_seconds:.2f}s)")

    
    print("\n🔹 Step 3: Adding tests...")
    result3 = await client.execute(
        "Write pytest tests for the Calculator class"
    )
    print(f"   Status: {result3.status} ({result3.execution_time_seconds:.2f}s)")

    
    print("\n" + "=" * 80)
    print("FINAL REPORT (Step 3):")
    print("=" * 80)
    print(result3.report)

    
    history = client.get_session_history()
    print(f"\nSession has {len(history)} messages")


async def example_with_context():
    """Example with additional context."""
    print("\n\n" + "=" * 80)
    print("Example 3: Task with Context")
    print("=" * 80)

    client = SWEClient(provider="openai")

    result = await client.execute(
        task="Create database models for a blog application",
        context={
            "framework": "Django",
            "database": "PostgreSQL",
            "requirements": [
                "User model with authentication",
                "Blog post model with title, content, author",
                "Comment model with author and timestamp"
            ]
        }
    )

    print(f"\n Status: {result.status}")
    print(f"⏱️  Time: {result.execution_time_seconds:.2f}s")
    print("\n" + "=" * 80)
    print("REPORT:")
    print("=" * 80)
    print(result.report[:1000] + "..." if len(result.report) > 1000 else result.report)


async def main():
    """Run all examples."""
    print("\n🚀 SWE Multi-Agent Orchestrator - Quick Start Examples\n")

    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print(" Warning: OPENAI_API_KEY not set!")
        print("   Set it with: export OPENAI_API_KEY='your-key'")
        print("   Or use --provider local for testing\n")
        return

    try:
        # Run examples
        await example_basic()
        await example_session()
        await example_with_context()

        print("\n\n" + "=" * 80)
        print("✨ All examples completed successfully!")
        print("=" * 80)
        print("\nNext steps:")
        print("  - Check out examples/swe_orchestrator_examples.md for more")
        print("  - Try the CLI: python -m sec_agents.cli swe run 'your task'")
        print("  - Explore the API endpoints in the documentation")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
