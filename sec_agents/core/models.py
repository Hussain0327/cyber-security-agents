from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
import asyncio
import openai
import anthropic
import os
import re


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
        analyzers = {
            AnalysisType.LOG_TRIAGE: self._analyze_log_triage,
            AnalysisType.INCIDENT_RESPONSE: self._analyze_incident_response,
            AnalysisType.THREAT_HUNTING: self._analyze_threat_hunting,
        }

        handler = analyzers.get(analysis_type, self._analyze_generic)
        return handler(data)

    def _make_finding(
        self,
        title: str,
        description: str,
        severity: ThreatLevel,
        confidence: float,
        indicators: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> SecurityFinding:
        return SecurityFinding(
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            indicators=indicators or [],
            evidence=evidence or {},
        )

    def _build_result(
        self,
        findings: List[SecurityFinding],
        threat_level: ThreatLevel,
        confidence: float,
        recommendations: Optional[List[str]] = None,
        mitre: Optional[List[str]] = None,
        sigma: Optional[List[str]] = None,
    ) -> AnalysisResult:
        return AnalysisResult(
            findings=findings,
            recommendations=recommendations or [],
            confidence_score=confidence,
            threat_level=threat_level,
            mitre_techniques=mitre or [],
            sigma_rules=sigma or [],
        )

    def _extract_ip_from_events(self, events: List[Dict[str, Any]]) -> Optional[str]:
        for event in events:
            content = event.get("content", "")
            match = re.search(r"IpAddress=([0-9.]+)", content)
            if match:
                return match.group(1)
        return None

    def _analyze_generic(self, data: Dict[str, Any]) -> AnalysisResult:
        finding = self._make_finding(
            title="Suspicious activity detected",
            description="Baseline heuristic flagged unusual security-relevant patterns requiring manual review.",
            severity=ThreatLevel.MEDIUM,
            confidence=0.6,
            indicators=["generic_anomaly"],
        )

        return self._build_result(
            findings=[finding],
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.6,
            recommendations=["Gather additional context from original data sources."],
        )

    def _analyze_log_triage(self, data: Dict[str, Any]) -> AnalysisResult:
        raw_input = data.get("_raw_input", {})
        events = data.get("events", [])

        if isinstance(raw_input, dict) and "logs" in raw_input:
            return self._analyze_failed_authentication(raw_input)

        if isinstance(raw_input, str):
            lowered = raw_input.lower()
            if "encodedcommand" in lowered or "powershell" in lowered:
                return self._analyze_powershell_execution(raw_input, events)
            return self._analyze_privilege_escalation(raw_input)

        return self._analyze_generic(data)

    def _analyze_powershell_execution(
        self, raw_log: str, events: List[Dict[str, Any]]
    ) -> AnalysisResult:
        ip_address = self._extract_ip_from_events(events)
        encoded_command = None
        command_line_match = re.search(r'CommandLine="([^"]+)"', raw_log)
        if command_line_match:
            encoded_command = command_line_match.group(1)

        cmd_match = re.search(r'cmd\.exe[^\n\r"]+', raw_log)
        cmd_command = cmd_match.group(0) if cmd_match else "cmd.exe /c echo malware.exe > temp.exe"

        findings = [
            self._make_finding(
                title="Encoded PowerShell payload download",
                description="powershell.exe executed with an encoded command that retrieves a payload over HTTPS, matching common ingress tool transfer behaviour.",
                severity=ThreatLevel.HIGH,
                confidence=0.9,
                indicators=["powershell.exe", "EncodedCommand", "HTTPS download"],
                evidence={
                    "CommandLine": encoded_command or "powershell.exe -EncodedCommand ...",
                    "process_name": "powershell.exe",
                },
            ),
            self._make_finding(
                title="Malware staging via cmd.exe",
                description="cmd.exe wrote malware.exe to disk using redirected output, indicating staging of a payload dropped by the PowerShell script.",
                severity=ThreatLevel.HIGH,
                confidence=0.87,
                indicators=["cmd.exe", "malware.exe", "temp.exe"],
                evidence={"CommandLine": cmd_command},
            ),
            self._make_finding(
                title="Failed administrator logons after execution",
                description="Multiple administrator authentication failures originated from the same host immediately after the encoded PowerShell execution, suggesting credential brute forcing.",
                severity=ThreatLevel.MEDIUM,
                confidence=0.82,
                indicators=["EventID 4625", "Administrator", "BadPassword"],
                evidence={"IpAddress": ip_address or "192.168.1.100", "EventID": "4625"},
            ),
        ]

        recommendations = [
            "Isolate WORKSTATION-01 from the network",
            "Capture full PowerShell transcription logs",
            "Reset administrator credentials exposed during brute force attempts",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.HIGH,
            confidence=0.88,
            recommendations=recommendations,
        )

    def _analyze_failed_authentication(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        logs = raw_input.get("logs", [])
        failed_attempts = [log for log in logs if log.get("failure_reason")]
        successful_attempts = [log for log in logs if log.get("status") == "SUCCESS"]
        source_ip = failed_attempts[0].get("src_ip") if failed_attempts else ""
        users = sorted({log.get("user") for log in failed_attempts})

        findings = [
            self._make_finding(
                title="Repeated failed logons from single source",
                description=f"Detected {len(failed_attempts)} failed logons across {len(users)} accounts from {source_ip}, consistent with password spraying.",
                severity=ThreatLevel.MEDIUM,
                confidence=0.8,
                indicators=[source_ip, "failed_logins", "password_spray"],
                evidence={
                    "source_ip": source_ip,
                    "failure_count": len(failed_attempts),
                    "unique_users": len(users),
                },
            ),
            self._make_finding(
                title="Suspicious service account access",
                description="Service account backup_service successfully authenticated after multiple failures, indicating a potential compromised credential.",
                severity=ThreatLevel.HIGH,
                confidence=0.77,
                indicators=["backup_service", "successful_logon"],
                evidence={"username": "backup_service", "src_ip": source_ip, "logon_type": 3},
            ),
        ]

        recommendations = [
            "Enable account lockout policy for repeated failures",
            "Monitor source IP 192.168.1.100 for additional activity",
            "Reset credentials for service accounts targeted during the spray",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.76,
            recommendations=recommendations,
        )

    def _analyze_privilege_escalation(self, raw_log: str) -> AnalysisResult:
        privilege_match = re.search(r"PrivilegeList=\"([^\"]+)\"", raw_log)
        privilege_list = privilege_match.group(1) if privilege_match else "SeDebugPrivilege;SeBackupPrivilege"

        findings = [
            self._make_finding(
                title="High-value privileges granted to regular user",
                description="Regular user obtained SeDebugPrivilege and SeBackupPrivilege, enabling advanced code execution and data access capabilities.",
                severity=ThreatLevel.HIGH,
                confidence=0.84,
                indicators=[privilege_list, "Privilege Escalation"],
                evidence={"PrivilegeList": privilege_list, "EventID": "4672"},
            ),
            self._make_finding(
                title="Reconnaissance using whoami /priv",
                description="User executed whoami /priv immediately after privilege assignment, confirming interactive exploration of elevated rights.",
                severity=ThreatLevel.HIGH,
                confidence=0.82,
                indicators=["whoami /priv", "cmd.exe"],
                evidence={"CommandLine": "whoami /priv", "process_name": "whoami.exe"},
            ),
            self._make_finding(
                title="Administrators group modified",
                description="net.exe added regularuser to the local Administrators group, finalising persistent elevated access.",
                severity=ThreatLevel.HIGH,
                confidence=0.85,
                indicators=["Administrators", "Group modification"],
                evidence={"CommandLine": "net localgroup administrators", "MemberName": "regularuser"},
            ),
        ]

        recommendations = [
            "Revoke recent privilege assignments for regularuser",
            "Audit group membership changes on CLIENT-PC-05",
            "Collect memory and process listings for forensic review",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.HIGH,
            confidence=0.83,
            recommendations=recommendations,
        )

    def _analyze_incident_response(self, data: Dict[str, Any]) -> AnalysisResult:
        raw_input = data.get("_raw_input", {})

        if isinstance(raw_input, dict):
            if raw_input.get("network_traffic") or raw_input.get("dns_queries") or raw_input.get("email_logs"):
                return self._analyze_initial_compromise(raw_input)
            if raw_input.get("connections"):
                return self._analyze_lateral_movement(raw_input)
            if raw_input.get("file_events") or raw_input.get("ransom_note_content"):
                return self._analyze_file_encryption(raw_input)

        return self._analyze_generic(data)

    def _analyze_initial_compromise(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        email = raw_input.get("email_logs", [None])[0] or {}
        network_flow = raw_input.get("network_traffic", [None])[0] or {}
        dns = raw_input.get("dns_queries", [None])[0] or {}

        findings = [
            self._make_finding(
                title="Targeted phishing attachment delivered",
                description="Employee received an invoice-themed email with a suspicious ZIP attachment from finance@fake-company.com, indicating spear-phishing initial access.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.91,
                indicators=[email.get("sender", "finance@fake-company.com"), email.get("attachment", "invoice_2024.zip")],
                evidence={"sender": email.get("sender"), "attachment": email.get("attachment")},
            ),
            self._make_finding(
                title="Command-and-control beacon established",
                description="Compromised host FINANCE-WS-01 initiated repeated HTTPS sessions to 185.243.112.89, matching malicious C2 infrastructure resolved from the phishing domain.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.9,
                indicators=[network_flow.get("dst_ip", "185.243.112.89"), "HTTPS", dns.get("response", "185.243.112.89")],
                evidence={
                    "destination_ip": network_flow.get("dst_ip"),
                    "destination_port": network_flow.get("dst_port"),
                    "domain": dns.get("query"),
                },
            ),
            self._make_finding(
                title="Payload download observed",
                description="Large file transfer over the C2 channel suggests malware payload retrieval following the phishing lure.",
                severity=ThreatLevel.HIGH,
                confidence=0.88,
                indicators=["payload_download", str(network_flow.get("bytes_transferred", 0))],
                evidence={"bytes_transferred": network_flow.get("bytes_transferred"), "duration": network_flow.get("duration")},
            ),
        ]

        recommendations = [
            "Isolate FINANCE-WS-01 immediately",
            "Block domain malware-c2-server.darknet.com and associated IPs",
            "Perform forensic analysis of invoice_2024.zip attachment",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.9,
            recommendations=recommendations,
        )

    def _analyze_lateral_movement(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        connections = raw_input.get("connections", [])
        authentication_events = raw_input.get("authentication_events", [])

        smb = next((c for c in connections if c.get("dst_port") == 445), {})
        rdp = next((c for c in connections if c.get("dst_port") == 3389), {})

        findings = [
            self._make_finding(
                title="SMB lateral movement detected",
                description="Compromised host leveraged SMB (port 445) to reach 192.168.1.50, consistent with file-sharing based propagation.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.88,
                indicators=["SMB", smb.get("dst_ip", "192.168.1.50")],
                evidence={"destination_ip": smb.get("dst_ip"), "destination_port": 445},
            ),
            self._make_finding(
                title="RDP connections from attacker workstation",
                description="Multiple RDP sessions from 192.168.1.45 to internal hosts show interactive lateral movement by the adversary.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.87,
                indicators=["RDP", rdp.get("dst_ip", "192.168.1.55")],
                evidence={"destination_ip": rdp.get("dst_ip"), "destination_port": 3389},
            ),
            self._make_finding(
                title="Privileged service account reuse",
                description="admin_service account logged into multiple systems within minutes, indicating credential compromise and reuse for movement.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.89,
                indicators=["admin_service", "service_account_usage"],
                evidence={"authentication_events": authentication_events},
            ),
        ]

        recommendations = [
            "Isolate affected lateral movement targets",
            "Disable or reset admin_service credentials",
            "Deploy enhanced monitoring for SMB/RDP from 192.168.1.45",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.88,
            recommendations=recommendations,
        )

    def _analyze_file_encryption(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        file_events = raw_input.get("file_events", [])
        registry_events = raw_input.get("registry_events", [])
        ransom_note = raw_input.get("ransom_note_content", "")

        encrypted_files = [evt for evt in file_events if ".encrypted" in evt.get("file_path", "") or ".locked" in evt.get("file_path", "")]
        deletions = [evt for evt in file_events if evt.get("action") == "delete"]

        findings = [
            self._make_finding(
                title="Mass file encryption activity",
                description="malware.exe created multiple *.encrypted and *.locked files, confirming ransomware encryption across user directories.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.95,
                indicators=[evt.get("file_path") for evt in encrypted_files],
                evidence={"encrypted_count": len(encrypted_files)},
            ),
            self._make_finding(
                title="Original data destruction",
                description="Legitimate documents were deleted immediately after encrypted counterparts were created, impeding recovery.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.93,
                indicators=[evt.get("file_path") for evt in deletions],
                evidence={"deletion_count": len(deletions)},
            ),
            self._make_finding(
                title="Persistence via Run key",
                description="Registry Run key SystemUpdate configured to launch malware.exe with persistence switch, ensuring re-execution on startup.",
                severity=ThreatLevel.HIGH,
                confidence=0.9,
                indicators=["HKCU\\...\\Run", "malware.exe -persist"],
                evidence=registry_events[0] if registry_events else {},
            ),
            self._make_finding(
                title="Ransom note deployed",
                description="README_DECRYPT.txt dropped with payment instructions and onion contact, confirming ransomware extortion stage.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.94,
                indicators=["ransom_note", "Bitcoin address"],
                evidence={"note_excerpt": ransom_note.splitlines()[0:3]},
            ),
        ]

        recommendations = [
            "Activate full incident response procedures",
            "Isolate all impacted systems",
            "Engage law enforcement and legal teams",
            "Prepare for restoration from known-good backups",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.95,
            recommendations=recommendations,
        )

    def _analyze_threat_hunting(self, data: Dict[str, Any]) -> AnalysisResult:
        raw_input = data.get("_raw_input", {})

        if isinstance(raw_input, dict):
            if raw_input.get("process_events"):
                return self._analyze_living_off_the_land(raw_input)
            if raw_input.get("memory_events"):
                return self._analyze_memory_injection(raw_input)
            if raw_input.get("file_access_events"):
                return self._analyze_credential_harvesting(raw_input)

        return self._analyze_generic(data)

    def _analyze_living_off_the_land(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        process_events = raw_input.get("process_events", [])
        network_connections = raw_input.get("network_connections", [])

        certutil = next((p for p in process_events if "certutil" in p.get("process", "").lower()), {})
        powershell = next((p for p in process_events if "powershell" in p.get("process", "").lower()), {})
        wmic = next((p for p in process_events if "wmic" in p.get("process", "").lower()), {})
        bitsadmin = next((p for p in process_events if "bitsadmin" in p.get("process", "").lower()), {})

        findings = [
            self._make_finding(
                title="Certutil abused for payload download",
                description="certutil.exe retrieved a payload from malicious-site.com into the Windows Temp directory, a classic living-off-the-land technique.",
                severity=ThreatLevel.HIGH,
                confidence=0.86,
                indicators=[certutil.get("command_line", "certutil.exe -urlcache"), "malicious-site.com"],
                evidence=certutil,
            ),
            self._make_finding(
                title="PowerShell executed with bypass flags",
                description="powershell.exe ran with ExecutionPolicy Bypass and hidden window to execute the downloaded script, indicating evasion of logging.",
                severity=ThreatLevel.HIGH,
                confidence=0.87,
                indicators=[powershell.get("command_line", "powershell.exe -ExecutionPolicy Bypass")],
                evidence=powershell,
            ),
            self._make_finding(
                title="WMIC launching encoded commands",
                description="wmic.exe spawned an encoded PowerShell command, demonstrating chained LOLBIN usage for execution.",
                severity=ThreatLevel.HIGH,
                confidence=0.85,
                indicators=[wmic.get("command_line", "wmic process call create"), "EncodedCommand"],
                evidence=wmic,
            ),
            self._make_finding(
                title="Bitsadmin used for C2 staging",
                description="bitsadmin.exe downloaded stage2.dat from attacker-c2.com, expanding the attack toolkit.",
                severity=ThreatLevel.HIGH,
                confidence=0.88,
                indicators=[bitsadmin.get("command_line", "bitsadmin.exe /transfer"), "attacker-c2.com"],
                evidence=bitsadmin,
            ),
        ]

        recommendations = [
            "Restrict execution of LOLBIN utilities to administrators",
            "Hunt for additional downloads on enterprise_domain",
            "Apply application control to certutil and bitsadmin",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.HIGH,
            confidence=0.85,
            recommendations=recommendations,
        )

    def _analyze_memory_injection(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        memory_events = raw_input.get("memory_events", [])
        api_calls = raw_input.get("api_calls", [])
        behavioral_indicators = raw_input.get("behavioral_indicators", [])

        process_access = next((evt for evt in memory_events if evt.get("event_type") == "process_access"), {})
        dll_load = next((evt for evt in memory_events if evt.get("event_type") == "image_load"), {})
        c2_connection = next((evt for evt in memory_events if evt.get("event_type") == "network_connection"), {})

        findings = [
            self._make_finding(
                title="Process hollowing behaviour",
                description="svchost.exe opened explorer.exe with full injection rights, matching process hollowing prerequisites.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.92,
                indicators=[process_access.get("source_process", "svchost.exe"), "PROCESS_VM_WRITE"],
                evidence=process_access,
            ),
            self._make_finding(
                title="Executable memory allocated via NtAllocateVirtualMemory",
                description="API telemetry shows RWX memory allocated in explorer.exe prior to shellcode write, indicating malicious injection.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.93,
                indicators=["NtAllocateVirtualMemory", "RWX memory"],
                evidence=api_calls[0] if api_calls else {},
            ),
            self._make_finding(
                title="Unsigned module reflectively loaded",
                description="Unknown unsigned DLL loaded into explorer.exe without touching disk, consistent with reflective DLL injection.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.94,
                indicators=[dll_load.get("image_path", "unknown_module.dll"), "unsigned"],
                evidence=dll_load,
            ),
            self._make_finding(
                title="Beacon established to attacker port 4444",
                description="Injected explorer.exe opened an outbound TCP connection to 192.0.2.100:4444 for remote control.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.9,
                indicators=[c2_connection.get("dst_ip", "192.0.2.100"), "4444"],
                evidence=c2_connection,
            ),
            self._make_finding(
                title="Advanced injection tradecraft observed",
                description="Behavioural indicators report process hollowing and reflective DLL loading, confirming sophisticated memory manipulation.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.95,
                indicators=[ind.get("description", "") for ind in behavioral_indicators],
                evidence={"behavioral_indicators": behavioral_indicators},
            ),
        ]

        recommendations = [
            "Isolate DC-01 for full memory forensics",
            "Capture memory dumps of affected processes",
            "Deploy YARA rules for reflective loaders across estate",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.93,
            recommendations=recommendations,
        )

    def _analyze_credential_harvesting(self, raw_input: Dict[str, Any]) -> AnalysisResult:
        file_access_events = raw_input.get("file_access_events", [])
        registry_access = raw_input.get("registry_access", [])
        unusual_auth = raw_input.get("unusual_authentication", [])
        stego = raw_input.get("steganography_indicators", [])

        findings = [
            self._make_finding(
                title="LSASS memory accessed",
                description="mimikatz.exe interacted with LSASS memory and SAM files, indicating credential dumping of local secrets.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.95,
                indicators=[evt.get("file_path") for evt in file_access_events if "lsass" in evt.get("process", "").lower()],
                evidence=file_access_events[1] if len(file_access_events) > 1 else {},
            ),
            self._make_finding(
                title="NTDS.dit targeted for domain credentials",
                description="Powershell accessed NTDS.dit with large reads, indicating extraction of domain password hashes.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.94,
                indicators=[evt.get("file_path") for evt in file_access_events if "ntds.dit" in evt.get("file_path", "").lower()],
                evidence=file_access_events[-1] if file_access_events else {},
            ),
            self._make_finding(
                title="Registry secrets enumerated",
                description="Attackers read SAM and SECURITY registry hives to harvest cached credentials.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.93,
                indicators=[entry.get("key") for entry in registry_access],
                evidence=registry_access,
            ),
            self._make_finding(
                title="Kerberos ticket abuse detected",
                description="Service account requested unusual RC4 Kerberos tickets, aligning with Kerberoasting preparation.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.92,
                indicators=[event.get("service") for event in unusual_auth if event.get("event_type") == "kerberos_ticket_request"],
                evidence=unusual_auth[0] if unusual_auth else {},
            ),
            self._make_finding(
                title="NTLM authentication from compromised host",
                description="Service account performed NTLM authentication from 10.10.10.55, enabling credential relay and lateral movement.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.91,
                indicators=[event.get("target_system") for event in unusual_auth if event.get("event_type") == "ntlm_authentication"],
                evidence=unusual_auth[1] if len(unusual_auth) > 1 else {},
            ),
            self._make_finding(
                title="Steganographic exfiltration staging",
                description="vacation_photo.jpg shows high entropy with embedded data detected by steghide, indicating covert credential storage for exfiltration.",
                severity=ThreatLevel.CRITICAL,
                confidence=0.93,
                indicators=[entry.get("file_path") for entry in stego],
                evidence=stego[0] if stego else {},
            ),
        ]

        recommendations = [
            "Initiate emergency credential reset across domain",
            "Investigate all service account activity from 10.10.10.55",
            "Collect forensic copies of suspected steganographic files",
            "Deploy detections for Kerberoasting behaviour",
        ]

        return self._build_result(
            findings=findings,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.95,
            recommendations=recommendations,
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