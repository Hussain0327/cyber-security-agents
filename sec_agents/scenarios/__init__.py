import os
import yaml
from typing import Dict, List, Any
import glob

from ..core.graph import SecurityGraph
from ..core.models import AnalysisRequest, AnalysisType


async def get_available_scenarios() -> List[str]:
    scenarios_dir = os.path.dirname(__file__)
    scenario_files = glob.glob(os.path.join(scenarios_dir, "*.yaml"))
    return [os.path.basename(f).replace('.yaml', '') for f in scenario_files]


async def load_scenario(scenario_name: str) -> Dict[str, Any]:
    scenarios_dir = os.path.dirname(__file__)
    scenario_path = os.path.join(scenarios_dir, f"{scenario_name}.yaml")

    if not os.path.exists(scenario_path):
        raise FileNotFoundError(f"Scenario {scenario_name} not found")

    with open(scenario_path, 'r') as f:
        scenario = yaml.safe_load(f)

    return scenario


async def run_scenario(scenario_name: str, provider_type: str = "local") -> Dict[str, Any]:
    scenario = await load_scenario(scenario_name)

    graph = SecurityGraph(provider_type=provider_type)
    results = []

    for step in scenario.get('steps', []):
        request = AnalysisRequest(
            analysis_type=AnalysisType(step['analysis_type']),
            data=step['input_data'],
            context=step.get('context', {})
        )

        result = await graph.analyze(request)
        results.append({
            'step': step['name'],
            'result': result.dict(),
            'expected': step.get('expected_output', {})
        })

    return {
        'scenario': scenario_name,
        'metadata': scenario.get('metadata', {}),
        'results': results,
        'success': True
    }