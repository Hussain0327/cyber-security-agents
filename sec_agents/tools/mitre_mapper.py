from typing import List, Dict, Any, Optional, Set
import re
import json

from ..core.models import SecurityFinding


class MITREMapper:
    def __init__(self):
        self.technique_map = {
            # Execution
            'T1059': ['command', 'shell', 'powershell', 'cmd', 'bash', 'script'],
            'T1053': ['scheduled', 'task', 'cron', 'at', 'schtasks'],
            'T1569': ['service', 'systemctl', 'sc.exe', 'net start'],

            # Persistence
            'T1547': ['startup', 'autorun', 'registry', 'run key'],
            'T1053': ['scheduled task', 'persistence'],
            'T1136': ['account', 'user creation', 'useradd', 'net user'],

            # Privilege Escalation
            'T1068': ['exploit', 'vulnerability', 'privilege escalation'],
            'T1055': ['injection', 'dll injection', 'process hollowing'],
            'T1134': ['token', 'impersonation', 'runas'],

            # Defense Evasion
            'T1027': ['obfuscation', 'encoding', 'packing', 'encryption'],
            'T1562': ['disable', 'defender', 'antivirus', 'firewall'],
            'T1070': ['clear', 'delete', 'wevtutil', 'log deletion'],

            # Credential Access
            'T1003': ['dump', 'lsass', 'sam', 'credential'],
            'T1110': ['brute force', 'password spray', 'credential stuffing'],
            'T1552': ['password', 'unsecured credential', 'clear text'],

            # Discovery
            'T1083': ['file discovery', 'dir', 'ls', 'find'],
            'T1057': ['process discovery', 'tasklist', 'ps', 'get-process'],
            'T1018': ['remote system discovery', 'ping', 'nslookup'],

            # Lateral Movement
            'T1021': ['remote services', 'rdp', 'ssh', 'winrm'],
            'T1570': ['lateral tool transfer', 'psexec', 'wmic'],
            'T1550': ['use alternate authentication', 'pass the hash'],

            # Collection
            'T1560': ['archive', 'compress', 'zip', 'rar'],
            'T1005': ['data from local system', 'file collection'],
            'T1113': ['screen capture', 'screenshot'],

            # Command and Control
            'T1071': ['application layer protocol', 'http', 'https', 'dns'],
            'T1573': ['encrypted channel', 'ssl', 'tls'],
            'T1105': ['ingress tool transfer', 'download', 'upload'],

            # Exfiltration
            'T1041': ['exfiltration', 'c2 channel', 'data transfer'],
            'T1048': ['exfiltration alternative protocol', 'dns tunneling'],
            'T1567': ['web service', 'cloud storage', 'dropbox'],

            # Impact
            'T1486': ['encrypt', 'ransomware', 'crypto'],
            'T1490': ['inhibit recovery', 'shadow copy', 'backup deletion'],
            'T1529': ['system shutdown', 'restart', 'shutdown'],
        }

        self.sub_techniques = {
            'T1059.001': ['powershell'],
            'T1059.003': ['cmd', 'command prompt', 'cmd.exe'],
            'T1059.004': ['unix shell', 'bash', 'sh'],
            'T1021.001': ['rdp', 'remote desktop'],
            'T1021.002': ['smb', 'admin shares', 'c$'],
            'T1021.003': ['distributed com', 'dcom'],
            'T1003.001': ['lsass memory', 'mimikatz'],
            'T1003.002': ['security account manager', 'sam'],
            'T1003.003': ['ntds', 'ntds.dit'],
        }

        self.tactic_map = {
            'initial_access': ['T1566', 'T1190', 'T1133', 'T1078'],
            'execution': ['T1059', 'T1053', 'T1569', 'T1204'],
            'persistence': ['T1547', 'T1053', 'T1136', 'T1543'],
            'privilege_escalation': ['T1068', 'T1055', 'T1134', 'T1548'],
            'defense_evasion': ['T1027', 'T1562', 'T1070', 'T1055'],
            'credential_access': ['T1003', 'T1110', 'T1552', 'T1558'],
            'discovery': ['T1083', 'T1057', 'T1018', 'T1033'],
            'lateral_movement': ['T1021', 'T1570', 'T1550', 'T1210'],
            'collection': ['T1560', 'T1005', 'T1113', 'T1125'],
            'command_and_control': ['T1071', 'T1573', 'T1105', 'T1095'],
            'exfiltration': ['T1041', 'T1048', 'T1567', 'T1020'],
            'impact': ['T1486', 'T1490', 'T1529', 'T1485'],
        }

    async def map_finding(self, finding: SecurityFinding) -> List[str]:
        techniques = set()

        text_content = f"{finding.title} {finding.description}".lower()

        for technique_id, keywords in self.technique_map.items():
            for keyword in keywords:
                if keyword.lower() in text_content:
                    techniques.add(technique_id)

        for sub_technique_id, keywords in self.sub_techniques.items():
            for keyword in keywords:
                if keyword.lower() in text_content:
                    techniques.add(sub_technique_id)

        for indicator in finding.indicators:
            indicator_lower = indicator.lower()
            for technique_id, keywords in self.technique_map.items():
                for keyword in keywords:
                    if keyword in indicator_lower:
                        techniques.add(technique_id)

        if finding.evidence:
            evidence_text = str(finding.evidence).lower()
            for technique_id, keywords in self.technique_map.items():
                for keyword in keywords:
                    if keyword in evidence_text:
                        techniques.add(technique_id)

        if not techniques:
            techniques.add('T1059')

        return sorted(list(techniques))

    async def map_tactics(self, techniques: List[str]) -> List[str]:
        tactics = set()

        for technique in techniques:
            base_technique = technique.split('.')[0]

            for tactic, tactic_techniques in self.tactic_map.items():
                if base_technique in tactic_techniques:
                    tactics.add(tactic)

        return sorted(list(tactics))

    async def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        technique_details = {
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'description': 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
                'platforms': ['Linux', 'macOS', 'Windows'],
                'tactics': ['Execution'],
                'data_sources': ['Command: Command Execution', 'Process: Process Creation']
            },
            'T1053': {
                'name': 'Scheduled Task/Job',
                'description': 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',
                'platforms': ['Linux', 'macOS', 'Windows'],
                'tactics': ['Execution', 'Persistence', 'Privilege Escalation'],
                'data_sources': ['Command: Command Execution', 'File: File Creation', 'Process: Process Creation']
            },
            'T1003': {
                'name': 'OS Credential Dumping',
                'description': 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
                'platforms': ['Linux', 'macOS', 'Windows'],
                'tactics': ['Credential Access'],
                'data_sources': ['Command: Command Execution', 'File: File Access', 'Process: Process Creation']
            },
            'T1055': {
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes in order to evade process-based defenses.',
                'platforms': ['Linux', 'macOS', 'Windows'],
                'tactics': ['Defense Evasion', 'Privilege Escalation'],
                'data_sources': ['Process: OS API Execution', 'Process: Process Access', 'Process: Process Modification']
            },
            'T1021': {
                'name': 'Remote Services',
                'description': 'Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.',
                'platforms': ['Linux', 'macOS', 'Windows'],
                'tactics': ['Lateral Movement'],
                'data_sources': ['Logon Session: Logon Session Creation', 'Network Traffic: Network Connection Creation']
            }
        }

        if technique_id in technique_details:
            return technique_details[technique_id]
        else:
            base_technique = technique_id.split('.')[0]
            if base_technique in technique_details:
                details = technique_details[base_technique].copy()
                details['sub_technique'] = technique_id
                return details

        return {
            'name': f'Technique {technique_id}',
            'description': f'MITRE ATT&CK technique {technique_id}',
            'platforms': ['Unknown'],
            'tactics': ['Unknown'],
            'data_sources': ['Unknown']
        }

    async def generate_attack_chain(self, techniques: List[str]) -> Dict[str, Any]:
        tactics_order = [
            'initial_access',
            'execution',
            'persistence',
            'privilege_escalation',
            'defense_evasion',
            'credential_access',
            'discovery',
            'lateral_movement',
            'collection',
            'command_and_control',
            'exfiltration',
            'impact'
        ]

        attack_chain = {}
        technique_tactics = {}

        for technique in techniques:
            tactics = await self.map_tactics([technique])
            technique_tactics[technique] = tactics

        for tactic in tactics_order:
            tactic_techniques = []
            for technique, tactics in technique_tactics.items():
                if tactic in tactics:
                    tactic_techniques.append(technique)
            if tactic_techniques:
                attack_chain[tactic] = tactic_techniques

        return {
            'attack_chain': attack_chain,
            'timeline': tactics_order,
            'coverage': {
                'tactics_covered': len(attack_chain),
                'total_tactics': len(tactics_order),
                'techniques_mapped': len(techniques)
            }
        }

    async def get_mitigations(self, techniques: List[str]) -> Dict[str, List[str]]:
        mitigation_map = {
            'T1059': [
                'M1038: Execution Prevention',
                'M1049: Antivirus/Antimalware',
                'M1021: Restrict Web-Based Content'
            ],
            'T1053': [
                'M1026: Privileged Account Management',
                'M1018: User Account Management',
                'M1047: Audit'
            ],
            'T1003': [
                'M1027: Password Policies',
                'M1026: Privileged Account Management',
                'M1043: Credential Access Protection'
            ],
            'T1055': [
                'M1040: Behavior Prevention on Endpoint',
                'M1026: Privileged Account Management'
            ],
            'T1021': [
                'M1032: Multi-factor Authentication',
                'M1026: Privileged Account Management',
                'M1035: Limit Access to Resource Over Network'
            ]
        }

        mitigations = {}
        for technique in techniques:
            base_technique = technique.split('.')[0]
            if base_technique in mitigation_map:
                mitigations[technique] = mitigation_map[base_technique]
            else:
                mitigations[technique] = ['M1047: Audit', 'M1049: Antivirus/Antimalware']

        return mitigations

    async def calculate_risk_score(self, techniques: List[str]) -> Dict[str, Any]:
        technique_scores = {
            'T1059': 7.5,
            'T1053': 6.8,
            'T1003': 8.9,
            'T1055': 8.2,
            'T1021': 7.1,
            'T1027': 6.5,
            'T1110': 7.8,
            'T1083': 5.2,
            'T1486': 9.5,
            'T1105': 7.3
        }

        scores = []
        for technique in techniques:
            base_technique = technique.split('.')[0]
            score = technique_scores.get(base_technique, 6.0)
            scores.append(score)

        if not scores:
            return {'risk_score': 0.0, 'risk_level': 'low'}

        avg_score = sum(scores) / len(scores)
        max_score = max(scores)

        adjusted_score = (avg_score * 0.6) + (max_score * 0.4)

        if adjusted_score >= 8.5:
            risk_level = 'critical'
        elif adjusted_score >= 7.0:
            risk_level = 'high'
        elif adjusted_score >= 5.0:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'risk_score': round(adjusted_score, 2),
            'risk_level': risk_level,
            'technique_count': len(techniques),
            'max_technique_score': max_score,
            'avg_technique_score': round(avg_score, 2)
        }