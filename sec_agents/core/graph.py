from typing import Dict, Any, List, TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
import logging

from .models import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisType,
    SecurityProvider,
    get_provider,
    ThreatLevel,
    SecurityFinding,
)
from ..tools.parsers import LogParser, NetworkParser, FileParser
from ..tools.sigma_builder import SigmaRuleBuilder
from ..tools.mitre_mapper import MITREMapper

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], "The messages in the conversation"]
    analysis_request: AnalysisRequest
    parsed_data: Dict[str, Any]
    findings: List[SecurityFinding]
    mitre_techniques: List[str]
    sigma_rules: List[str]
    recommendations: List[str]
    confidence_score: float
    threat_level: ThreatLevel
    provider: SecurityProvider


class SecurityGraph:
    def __init__(self, provider_type: str = "local"):
        self.provider = get_provider(provider_type)
        self.log_parser = LogParser()
        self.network_parser = NetworkParser()
        self.file_parser = FileParser()
        self.sigma_builder = SigmaRuleBuilder()
        self.mitre_mapper = MITREMapper()
        self.graph = self._build_graph()

    def _enrich_parsed_data(self, parsed_data: Any, request: AnalysisRequest) -> Dict[str, Any]:
        if isinstance(parsed_data, dict):
            enriched = dict(parsed_data)
            enriched.setdefault("_raw_input", request.data)
            if request.context:
                enriched.setdefault("_context", request.context)
            return enriched

        return {
            "value": parsed_data,
            "_raw_input": request.data,
            "_context": request.context or {},
        }

    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(AgentState)

        workflow.add_node("parse_data", self._parse_data_node)
        workflow.add_node("initial_analysis", self._initial_analysis_node)
        workflow.add_node("map_mitre", self._map_mitre_node)
        workflow.add_node("generate_sigma", self._generate_sigma_node)
        workflow.add_node("generate_recommendations", self._generate_recommendations_node)
        workflow.add_node("finalize_analysis", self._finalize_analysis_node)

        workflow.set_entry_point("parse_data")

        workflow.add_edge("parse_data", "initial_analysis")
        workflow.add_edge("initial_analysis", "map_mitre")
        workflow.add_edge("map_mitre", "generate_sigma")
        workflow.add_edge("generate_sigma", "generate_recommendations")
        workflow.add_edge("generate_recommendations", "finalize_analysis")
        workflow.add_edge("finalize_analysis", END)

        return workflow.compile()

    async def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        initial_state = AgentState(
            messages=[HumanMessage(content=f"Analyzing {request.analysis_type} data")],
            analysis_request=request,
            parsed_data={},
            findings=[],
            mitre_techniques=[],
            sigma_rules=[],
            recommendations=[],
            confidence_score=0.0,
            threat_level=ThreatLevel.LOW,
            provider=self.provider,
        )

        final_state = await self.graph.ainvoke(initial_state)

        return AnalysisResult(
            findings=final_state["findings"],
            recommendations=final_state["recommendations"],
            confidence_score=final_state["confidence_score"],
            threat_level=final_state["threat_level"],
            mitre_techniques=final_state["mitre_techniques"],
            sigma_rules=final_state["sigma_rules"],
        )

    async def _parse_data_node(self, state: AgentState) -> AgentState:
        logger.info("Parsing input data")
        request = state["analysis_request"]
        parsed_data = {}

        try:
            if request.analysis_type == AnalysisType.LOG_TRIAGE:
                parsed_data = await self.log_parser.parse(request.data)
            elif request.analysis_type == AnalysisType.INCIDENT_RESPONSE:
                parsed_data = await self.network_parser.parse(request.data)
            elif request.analysis_type == AnalysisType.MALWARE_ANALYSIS:
                parsed_data = await self.file_parser.parse(request.data)
            else:
                parsed_data = request.data

            parsed_data = self._enrich_parsed_data(parsed_data, request)
            state["parsed_data"] = parsed_data
            state["messages"].append(
                AIMessage(content=f"Data parsed successfully: {len(parsed_data)} fields")
            )

        except Exception as e:
            logger.error(f"Data parsing failed: {str(e)}")
            state["parsed_data"] = self._enrich_parsed_data(request.data, request)
            state["messages"].append(
                AIMessage(content=f"Data parsing failed, using raw data: {str(e)}")
            )

        return state

    async def _initial_analysis_node(self, state: AgentState) -> AgentState:
        logger.info("Performing initial security analysis")
        provider = state["provider"]
        request = state["analysis_request"]
        parsed_data = state["parsed_data"]

        try:
            result = await provider.analyze_security_data(
                parsed_data, request.analysis_type
            )

            state["findings"] = result.findings
            state["confidence_score"] = result.confidence_score
            state["threat_level"] = result.threat_level
            state["messages"].append(
                AIMessage(content=f"Initial analysis complete: {len(result.findings)} findings")
            )

        except Exception as e:
            logger.error(f"Initial analysis failed: {str(e)}")
            state["findings"] = [
                SecurityFinding(
                    title="Analysis Error",
                    description=f"Initial analysis failed: {str(e)}",
                    severity=ThreatLevel.MEDIUM,
                    confidence=0.5,
                )
            ]
            state["confidence_score"] = 0.5
            state["threat_level"] = ThreatLevel.MEDIUM

        return state

    async def _map_mitre_node(self, state: AgentState) -> AgentState:
        logger.info("Mapping findings to MITRE ATT&CK techniques")
        findings = state["findings"]

        try:
            techniques = []
            for finding in findings:
                mapped_techniques = await self.mitre_mapper.map_finding(finding)
                techniques.extend(mapped_techniques)

            state["mitre_techniques"] = list(set(techniques))
            state["messages"].append(
                AIMessage(content=f"Mapped to {len(state['mitre_techniques'])} MITRE techniques")
            )

        except Exception as e:
            logger.error(f"MITRE mapping failed: {str(e)}")
            state["mitre_techniques"] = ["T1059"]

        return state

    async def _generate_sigma_node(self, state: AgentState) -> AgentState:
        logger.info("Generating Sigma rules")
        findings = state["findings"]
        parsed_data = state["parsed_data"]

        try:
            sigma_rules = []
            for finding in findings:
                rules = await self.sigma_builder.generate_rules(finding, parsed_data)
                sigma_rules.extend(rules)

            state["sigma_rules"] = sigma_rules
            state["messages"].append(
                AIMessage(content=f"Generated {len(sigma_rules)} Sigma rules")
            )

        except Exception as e:
            logger.error(f"Sigma rule generation failed: {str(e)}")
            state["sigma_rules"] = ["generic_suspicious_activity"]

        return state

    async def _generate_recommendations_node(self, state: AgentState) -> AgentState:
        logger.info("Generating security recommendations")
        findings = state["findings"]
        threat_level = state["threat_level"]

        recommendations = []

        if threat_level == ThreatLevel.CRITICAL:
            recommendations.extend([
                "Immediate isolation of affected systems",
                "Activate incident response team",
                "Preserve forensic evidence",
                "Notify stakeholders and authorities as required",
            ])
        elif threat_level == ThreatLevel.HIGH:
            recommendations.extend([
                "Investigate findings immediately",
                "Implement additional monitoring",
                "Review and update security controls",
                "Consider threat hunting activities",
            ])
        else:
            recommendations.extend([
                "Monitor for similar activities",
                "Review security logs regularly",
                "Update detection rules",
                "Conduct security awareness training",
            ])

        for finding in findings:
            if "password" in finding.description.lower():
                recommendations.append("Implement stronger password policies")
            if "network" in finding.description.lower():
                recommendations.append("Review network segmentation")
            if "malware" in finding.description.lower():
                recommendations.append("Update antivirus signatures")

        state["recommendations"] = list(set(recommendations))
        state["messages"].append(
            AIMessage(content=f"Generated {len(state['recommendations'])} recommendations")
        )

        return state

    async def _finalize_analysis_node(self, state: AgentState) -> AgentState:
        logger.info("Finalizing security analysis")

        num_findings = len(state["findings"])
        avg_confidence = sum(f.confidence for f in state["findings"]) / max(num_findings, 1)

        if num_findings > 5 or state["threat_level"] == ThreatLevel.CRITICAL:
            state["confidence_score"] = min(avg_confidence + 0.1, 1.0)
        else:
            state["confidence_score"] = avg_confidence

        state["messages"].append(
            AIMessage(
                content=f"Analysis complete: {num_findings} findings, "
                f"threat level {state['threat_level']}, "
                f"confidence {state['confidence_score']:.2f}"
            )
        )

        logger.info(
            f"Security analysis completed: {num_findings} findings, "
            f"threat level {state['threat_level']}"
        )

        return state