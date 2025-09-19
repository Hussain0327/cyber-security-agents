import pytest
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List

from ..scenarios import run_scenario, get_available_scenarios
from ..core.models import AnalysisType, ThreatLevel


class TestScenarios:
    @pytest.fixture
    def golden_data(self) -> Dict[str, Any]:
        golden_file = Path(__file__).parent / "golden_results.json"
        if golden_file.exists():
            with open(golden_file, 'r') as f:
                return json.load(f)
        return {}

    @pytest.mark.asyncio
    async def test_log_triage_scenario(self, golden_data):
        scenario_name = "log_triage"
        result = await run_scenario(scenario_name)

        assert result["success"] is True
        assert len(result["results"]) > 0

        if scenario_name in golden_data:
            await self._compare_with_golden(result, golden_data[scenario_name])

    @pytest.mark.asyncio
    async def test_incident_response_scenario(self, golden_data):
        scenario_name = "incident_response"
        result = await run_scenario(scenario_name)

        assert result["success"] is True
        assert len(result["results"]) > 0

        critical_findings = [
            r for r in result["results"]
            if any(f.get("severity") == "critical" for f in r["result"].get("findings", []))
        ]
        assert len(critical_findings) > 0

        if scenario_name in golden_data:
            await self._compare_with_golden(result, golden_data[scenario_name])

    @pytest.mark.asyncio
    async def test_threat_hunting_scenario(self, golden_data):
        scenario_name = "threat_hunting"
        result = await run_scenario(scenario_name)

        assert result["success"] is True
        assert len(result["results"]) > 0

        mitre_techniques = []
        for step_result in result["results"]:
            mitre_techniques.extend(step_result["result"].get("mitre_techniques", []))

        assert len(mitre_techniques) > 0
        assert any("T1059" in tech for tech in mitre_techniques)

        if scenario_name in golden_data:
            await self._compare_with_golden(result, golden_data[scenario_name])

    async def _compare_with_golden(self, actual: Dict[str, Any], expected: Dict[str, Any]):
        assert actual["scenario"] == expected["scenario"]

        actual_steps = len(actual["results"])
        expected_steps = len(expected["results"])
        assert actual_steps == expected_steps, f"Expected {expected_steps} steps, got {actual_steps}"

        for i, (actual_step, expected_step) in enumerate(zip(actual["results"], expected["results"])):
            step_name = actual_step["step"]

            actual_findings = len(actual_step["result"]["findings"])
            expected_findings = expected_step["result"]["findings_count"]

            assert actual_findings >= expected_findings * 0.8, \
                f"Step {step_name}: Expected at least {expected_findings * 0.8} findings, got {actual_findings}"

            actual_threat_level = actual_step["result"]["threat_level"]
            expected_threat_level = expected_step["result"]["threat_level"]

            threat_level_order = ["low", "medium", "high", "critical"]
            actual_level_idx = threat_level_order.index(actual_threat_level)
            expected_level_idx = threat_level_order.index(expected_threat_level)

            assert abs(actual_level_idx - expected_level_idx) <= 1, \
                f"Step {step_name}: Threat level mismatch. Expected {expected_threat_level}, got {actual_threat_level}"


class TestScenarioValidation:
    @pytest.mark.asyncio
    async def test_all_scenarios_loadable(self):
        scenarios = await get_available_scenarios()
        assert len(scenarios) > 0

        for scenario_name in scenarios:
            try:
                result = await run_scenario(scenario_name)
                assert result["success"] is True
                assert "results" in result
            except Exception as e:
                pytest.fail(f"Scenario {scenario_name} failed to run: {str(e)}")

    def test_scenario_yaml_structure(self):
        scenarios_dir = Path(__file__).parent.parent / "scenarios"
        yaml_files = list(scenarios_dir.glob("*.yaml"))

        assert len(yaml_files) > 0, "No scenario YAML files found"

        required_fields = ["name", "description", "steps", "metadata"]

        for yaml_file in yaml_files:
            with open(yaml_file, 'r') as f:
                scenario = yaml.safe_load(f)

            for field in required_fields:
                assert field in scenario, f"Missing required field '{field}' in {yaml_file.name}"

            assert len(scenario["steps"]) > 0, f"No steps defined in {yaml_file.name}"

            for i, step in enumerate(scenario["steps"]):
                step_required = ["name", "analysis_type", "input_data"]
                for field in step_required:
                    assert field in step, f"Step {i} missing '{field}' in {yaml_file.name}"

                assert step["analysis_type"] in [at.value for at in AnalysisType], \
                    f"Invalid analysis_type in step {i} of {yaml_file.name}"


class TestAnalysisQuality:
    @pytest.mark.asyncio
    async def test_analysis_consistency(self):
        scenario_name = "log_triage"
        results = []

        for _ in range(3):
            result = await run_scenario(scenario_name)
            results.append(result)

        for i in range(len(results[0]["results"])):
            step_results = [r["results"][i] for r in results]

            threat_levels = [sr["result"]["threat_level"] for sr in step_results]
            finding_counts = [len(sr["result"]["findings"]) for sr in step_results]

            max_findings = max(finding_counts)
            min_findings = min(finding_counts)
            assert (max_findings - min_findings) / max_findings <= 0.3, \
                "Finding count variance too high across runs"

    @pytest.mark.asyncio
    async def test_mitre_mapping_coverage(self):
        scenarios = await get_available_scenarios()

        for scenario_name in scenarios:
            result = await run_scenario(scenario_name)

            all_techniques = set()
            for step_result in result["results"]:
                techniques = step_result["result"].get("mitre_techniques", [])
                all_techniques.update(techniques)

            assert len(all_techniques) > 0, f"No MITRE techniques mapped for {scenario_name}"

            for technique in all_techniques:
                assert technique.startswith("T"), f"Invalid MITRE technique format: {technique}"

    @pytest.mark.asyncio
    async def test_sigma_rule_generation(self):
        scenario_name = "log_triage"
        result = await run_scenario(scenario_name)

        sigma_rules_generated = False
        for step_result in result["results"]:
            sigma_rules = step_result["result"].get("sigma_rules", [])
            if sigma_rules:
                sigma_rules_generated = True
                for rule in sigma_rules:
                    assert isinstance(rule, str), "Sigma rule should be a string"
                    assert len(rule) > 0, "Sigma rule should not be empty"

        assert sigma_rules_generated, "No Sigma rules were generated"


class TestPerformance:
    @pytest.mark.asyncio
    async def test_scenario_execution_time(self):
        import time

        scenario_name = "log_triage"
        start_time = time.time()

        result = await run_scenario(scenario_name)

        execution_time = time.time() - start_time

        assert result["success"] is True
        assert execution_time < 30, f"Scenario took too long: {execution_time:.2f} seconds"

    @pytest.mark.asyncio
    async def test_concurrent_scenario_execution(self):
        import asyncio

        scenarios = await get_available_scenarios()
        tasks = [run_scenario(scenario) for scenario in scenarios[:2]]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                pytest.fail(f"Concurrent execution failed for scenario {scenarios[i]}: {str(result)}")
            else:
                assert result["success"] is True


@pytest.mark.integration
class TestIntegrationScenarios:
    @pytest.mark.asyncio
    async def test_end_to_end_workflow(self):
        scenario_name = "incident_response"
        result = await run_scenario(scenario_name)

        assert result["success"] is True

        high_severity_findings = []
        for step_result in result["results"]:
            for finding in step_result["result"]["findings"]:
                if finding.get("severity") in ["high", "critical"]:
                    high_severity_findings.append(finding)

        assert len(high_severity_findings) > 0, "No high-severity findings detected"

        recommendations = []
        for step_result in result["results"]:
            recommendations.extend(step_result["result"].get("recommendations", []))

        assert len(recommendations) > 0, "No recommendations generated"
        assert any("isolate" in rec.lower() for rec in recommendations), \
            "Expected isolation recommendation for incident response"