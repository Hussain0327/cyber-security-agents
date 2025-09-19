#!/usr/bin/env python3
import click
import asyncio
import json
import yaml
from pathlib import Path
from typing import Optional
import logging

from .scenarios import run_scenario, get_available_scenarios
from .core.graph import SecurityGraph
from .core.models import AnalysisRequest, AnalysisType, get_provider
from .app.auth import generate_demo_token


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--provider', default='local', help='AI provider (openai, anthropic, local)')
@click.pass_context
def cli(ctx, verbose, provider):
    """Security Agents CLI - Cybersecurity AI analysis and response system"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['provider'] = provider

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


@cli.command()
@click.argument('scenario_name')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'yaml']), default='json', help='Output format')
@click.pass_context
def run(ctx, scenario_name, output, output_format):
    """Run a security analysis scenario"""
    async def _run_scenario():
        try:
            click.echo(f"Running scenario: {scenario_name}")
            result = await run_scenario(scenario_name, ctx.obj['provider'])

            if output:
                output_path = Path(output)
                if output_format == 'yaml':
                    with open(output_path, 'w') as f:
                        yaml.dump(result, f, default_flow_style=False)
                else:
                    with open(output_path, 'w') as f:
                        json.dump(result, f, indent=2, default=str)
                click.echo(f"Results saved to: {output_path}")
            else:
                if output_format == 'yaml':
                    click.echo(yaml.dump(result, default_flow_style=False))
                else:
                    click.echo(json.dumps(result, indent=2, default=str))

        except FileNotFoundError:
            click.echo(f"Error: Scenario '{scenario_name}' not found", err=True)
            click.echo("Available scenarios:")
            scenarios = await get_available_scenarios()
            for scenario in scenarios:
                click.echo(f"  - {scenario}")
        except Exception as e:
            click.echo(f"Error running scenario: {str(e)}", err=True)

    asyncio.run(_run_scenario())


@cli.command()
def list():
    """List available scenarios"""
    async def _list_scenarios():
        scenarios = await get_available_scenarios()
        click.echo("Available scenarios:")
        for scenario in scenarios:
            click.echo(f"  - {scenario}")

    asyncio.run(_list_scenarios())


@cli.command()
@click.argument('analysis_type', type=click.Choice([at.value for at in AnalysisType]))
@click.option('--data', required=True, help='Input data (JSON string or file path)')
@click.option('--context', help='Additional context (JSON string)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.pass_context
def analyze(ctx, analysis_type, data, context, output):
    """Perform ad-hoc security analysis"""
    async def _analyze():
        try:
            # Parse input data
            if Path(data).exists():
                with open(data, 'r') as f:
                    input_data = json.load(f)
            else:
                input_data = json.loads(data)

            # Parse context if provided
            context_data = {}
            if context:
                if Path(context).exists():
                    with open(context, 'r') as f:
                        context_data = json.load(f)
                else:
                    context_data = json.loads(context)

            # Create analysis request
            request = AnalysisRequest(
                analysis_type=AnalysisType(analysis_type),
                data=input_data,
                context=context_data
            )

            # Run analysis
            provider = get_provider(ctx.obj['provider'])
            graph = SecurityGraph(ctx.obj['provider'])

            click.echo(f"Analyzing {analysis_type} data...")
            result = await graph.analyze(request)

            # Output results
            result_dict = {
                "analysis_type": analysis_type,
                "findings": [f.dict() for f in result.findings],
                "recommendations": result.recommendations,
                "confidence_score": result.confidence_score,
                "threat_level": result.threat_level,
                "mitre_techniques": result.mitre_techniques,
                "sigma_rules": result.sigma_rules
            }

            if output:
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2, default=str)
                click.echo(f"Analysis results saved to: {output}")
            else:
                click.echo(json.dumps(result_dict, indent=2, default=str))

        except json.JSONDecodeError as e:
            click.echo(f"Error parsing JSON data: {str(e)}", err=True)
        except Exception as e:
            click.echo(f"Error during analysis: {str(e)}", err=True)

    asyncio.run(_analyze())


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def serve(host, port, reload):
    """Start the Security Agents API server"""
    try:
        import uvicorn
        from .app.main import app

        click.echo(f"Starting Security Agents API server on {host}:{port}")
        if reload:
            click.echo("Auto-reload enabled")

        uvicorn.run(
            "sec_agents.app.main:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except ImportError:
        click.echo("Error: uvicorn not installed. Install with: pip install uvicorn", err=True)
    except Exception as e:
        click.echo(f"Error starting server: {str(e)}", err=True)


@cli.command()
def auth():
    """Generate authentication token for API access"""
    try:
        token = generate_demo_token()
        click.echo("Generated authentication token:")
        click.echo(token)
        click.echo("\nUse this token in API requests:")
        click.echo(f"Authorization: Bearer {token}")
    except Exception as e:
        click.echo(f"Error generating token: {str(e)}", err=True)


@cli.command()
@click.option('--scenarios', is_flag=True, help='Run scenario tests')
@click.option('--integration', is_flag=True, help='Run integration tests')
@click.option('--verbose', '-v', is_flag=True, help='Verbose test output')
def test(scenarios, integration, verbose):
    """Run evaluation tests"""
    try:
        import pytest

        args = []
        if scenarios:
            args.append("evals/test_scenarios.py")
        if integration:
            args.append("-m")
            args.append("integration")
        if verbose:
            args.append("-v")

        if not args:
            args = ["evals/"]

        click.echo("Running evaluation tests...")
        exit_code = pytest.main(args)

        if exit_code == 0:
            click.echo("All tests passed!")
        else:
            click.echo(f"Tests failed with exit code: {exit_code}", err=True)

    except ImportError:
        click.echo("Error: pytest not installed. Install with: pip install pytest", err=True)
    except Exception as e:
        click.echo(f"Error running tests: {str(e)}", err=True)


@cli.command()
@click.argument('output_dir', type=click.Path())
@click.option('--format', 'output_format', type=click.Choice(['json', 'yaml', 'md']), default='json')
def export(output_dir, output_format):
    """Export scenarios and results for external use"""
    async def _export():
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            scenarios = await get_available_scenarios()
            click.echo(f"Exporting {len(scenarios)} scenarios to {output_path}")

            for scenario_name in scenarios:
                result = await run_scenario(scenario_name, "local")  # Use local for export

                if output_format == 'yaml':
                    file_path = output_path / f"{scenario_name}.yaml"
                    with open(file_path, 'w') as f:
                        yaml.dump(result, f, default_flow_style=False)
                elif output_format == 'md':
                    file_path = output_path / f"{scenario_name}.md"
                    with open(file_path, 'w') as f:
                        f.write(f"# {scenario_name.title()} Scenario Results\n\n")
                        f.write(f"**Scenario:** {result['scenario']}\n\n")
                        f.write(f"**Success:** {result['success']}\n\n")
                        f.write("## Results\n\n")
                        for i, step_result in enumerate(result['results']):
                            f.write(f"### Step {i+1}: {step_result['step']}\n\n")
                            f.write(f"- **Findings:** {len(step_result['result']['findings'])}\n")
                            f.write(f"- **Threat Level:** {step_result['result']['threat_level']}\n")
                            f.write(f"- **Confidence:** {step_result['result']['confidence_score']:.2f}\n\n")
                else:
                    file_path = output_path / f"{scenario_name}.json"
                    with open(file_path, 'w') as f:
                        json.dump(result, f, indent=2, default=str)

                click.echo(f"  Exported: {file_path}")

            click.echo("Export completed successfully")

        except Exception as e:
            click.echo(f"Error during export: {str(e)}", err=True)

    asyncio.run(_export())


@cli.command()
@click.option('--config-file', type=click.Path(exists=True), help='Configuration file path')
def config(config_file):
    """Show or update configuration"""
    if config_file:
        try:
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            click.echo("Configuration loaded:")
            click.echo(yaml.dump(config_data, default_flow_style=False))
        except Exception as e:
            click.echo(f"Error loading config: {str(e)}", err=True)
    else:
        click.echo("Current configuration:")
        click.echo(f"Provider: {click.get_current_context().obj.get('provider', 'openai')}")
        click.echo(f"Verbose: {click.get_current_context().obj.get('verbose', False)}")


def main():
    """Entry point for the CLI"""
    cli()


if __name__ == '__main__':
    main()