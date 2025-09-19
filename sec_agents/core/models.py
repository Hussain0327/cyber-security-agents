from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
import asyncio
import openai
import anthropic
import os


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisType(str, Enum):
    LOG_TRIAGE = "log_triage"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    MALWARE_ANALYSIS = "malware_analysis"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"


class AnalysisRequest(BaseModel):
    analysis_type: AnalysisType
    data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    priority: Optional[str] = "medium"


class SecurityFinding(BaseModel):
    title: str
    description: str
    severity: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)
    indicators: List[str] = []
    evidence: Dict[str, Any] = {}


class AnalysisResult(BaseModel):
    findings: List[SecurityFinding]
    recommendations: List[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    threat_level: ThreatLevel
    mitre_techniques: List[str] = []
    sigma_rules: List[str] = []


class AnalysisResponse(BaseModel):
    request_id: str
    analysis_type: AnalysisType
    findings: List[SecurityFinding]
    recommendations: List[str]
    confidence_score: float
    threat_level: ThreatLevel
    mitre_techniques: List[str]
    sigma_rules: List[str]


class SecurityProvider(ABC):
    def __init__(self, model_name: str):
        self.model_name = model_name

    @abstractmethod
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.1
    ) -> str:
        pass

    @abstractmethod
    async def analyze_security_data(
        self,
        data: Dict[str, Any],
        analysis_type: AnalysisType
    ) -> AnalysisResult:
        pass


class OpenAIProvider(SecurityProvider):
    def __init__(self, model_name: str = "gpt-4o"):
        super().__init__(model_name)
        self.client = openai.AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.1
    ) -> str:
        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")

    async def analyze_security_data(
        self,
        data: Dict[str, Any],
        analysis_type: AnalysisType
    ) -> AnalysisResult:
        system_prompt = self._get_security_prompt(analysis_type)
        data_str = str(data)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this security data: {data_str}"}
        ]

        response = await self.generate_response(messages, max_tokens=2000)
        return self._parse_security_response(response)

    def _get_security_prompt(self, analysis_type: AnalysisType) -> str:
        prompts = {
            AnalysisType.LOG_TRIAGE: """You are a cybersecurity analyst specializing in log analysis.
            Analyze the provided log data for security threats, anomalies, and indicators of compromise.
            Focus on identifying suspicious patterns, unauthorized access attempts, and potential security incidents.""",

            AnalysisType.INCIDENT_RESPONSE: """You are an incident response specialist.
            Analyze the provided data to understand the scope, impact, and recommended response actions.
            Identify attack vectors, compromised systems, and containment strategies.""",

            AnalysisType.THREAT_HUNTING: """You are a threat hunter looking for advanced persistent threats.
            Analyze the data for subtle indicators of compromise, lateral movement, and sophisticated attack techniques.
            Focus on identifying patterns that may indicate ongoing threat actor activity.""",
        }
        return prompts.get(analysis_type, prompts[AnalysisType.LOG_TRIAGE])

    def _parse_security_response(self, response: str) -> AnalysisResult:
        findings = [
            SecurityFinding(
                title="Analysis Complete",
                description=response[:200] + "..." if len(response) > 200 else response,
                severity=ThreatLevel.MEDIUM,
                confidence=0.8,
            )
        ]

        return AnalysisResult(
            findings=findings,
            recommendations=["Review findings and implement suggested mitigations"],
            confidence_score=0.8,
            threat_level=ThreatLevel.MEDIUM,
            mitre_techniques=["T1059"],
            sigma_rules=["generic_suspicious_activity"],
        )


class AnthropicProvider(SecurityProvider):
    def __init__(self, model_name: str = "claude-3-sonnet-20240229"):
        super().__init__(model_name)
        self.client = anthropic.AsyncAnthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.1
    ) -> str:
        try:
            system_message = ""
            user_messages = []

            for msg in messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    user_messages.append(msg)

            response = await self.client.messages.create(
                model=self.model_name,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_message,
                messages=user_messages,
            )
            return response.content[0].text
        except Exception as e:
            raise Exception(f"Anthropic API error: {str(e)}")

    async def analyze_security_data(
        self,
        data: Dict[str, Any],
        analysis_type: AnalysisType
    ) -> AnalysisResult:
        system_prompt = self._get_security_prompt(analysis_type)
        data_str = str(data)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this security data: {data_str}"}
        ]

        response = await self.generate_response(messages, max_tokens=2000)
        return self._parse_security_response(response)

    def _get_security_prompt(self, analysis_type: AnalysisType) -> str:
        return OpenAIProvider._get_security_prompt(self, analysis_type)

    def _parse_security_response(self, response: str) -> AnalysisResult:
        return OpenAIProvider._parse_security_response(self, response)


class LocalProvider(SecurityProvider):
    def __init__(self, model_name: str = "local-model", endpoint: str = "http://localhost:8080"):
        super().__init__(model_name)
        self.endpoint = endpoint

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.1
    ) -> str:
        return "Local model response placeholder - implement based on your local LLM setup"

    async def analyze_security_data(
        self,
        data: Dict[str, Any],
        analysis_type: AnalysisType
    ) -> AnalysisResult:
        findings = [
            SecurityFinding(
                title="Local Analysis",
                description="Local model analysis placeholder",
                severity=ThreatLevel.LOW,
                confidence=0.6,
            )
        ]

        return AnalysisResult(
            findings=findings,
            recommendations=["Implement local model integration"],
            confidence_score=0.6,
            threat_level=ThreatLevel.LOW,
            mitre_techniques=[],
            sigma_rules=[],
        )


def get_provider(provider_type: str = "openai", model_name: Optional[str] = None) -> SecurityProvider:
    providers = {
        "openai": lambda: OpenAIProvider(model_name or "gpt-4o"),
        "anthropic": lambda: AnthropicProvider(model_name or "claude-3-sonnet-20240229"),
        "local": lambda: LocalProvider(model_name or "local-model"),
    }

    if provider_type not in providers:
        raise ValueError(f"Unknown provider type: {provider_type}")

    return providers[provider_type]()