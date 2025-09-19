import yaml
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

from ..core.models import SecurityFinding, ThreatLevel


class SigmaRuleBuilder:
    def __init__(self):
        self.rule_templates = {
            'process_creation': {
                'title': 'Suspicious Process Creation',
                'logsource': {
                    'category': 'process_creation',
                    'product': 'windows'
                },
                'detection': {
                    'selection': {},
                    'condition': 'selection'
                }
            },
            'network_connection': {
                'title': 'Suspicious Network Connection',
                'logsource': {
                    'category': 'network_connection',
                    'product': 'zeek'
                },
                'detection': {
                    'selection': {},
                    'condition': 'selection'
                }
            },
            'file_event': {
                'title': 'Suspicious File Activity',
                'logsource': {
                    'category': 'file_event',
                    'product': 'windows'
                },
                'detection': {
                    'selection': {},
                    'condition': 'selection'
                }
            },
            'authentication': {
                'title': 'Authentication Anomaly',
                'logsource': {
                    'category': 'authentication',
                    'product': 'windows'
                },
                'detection': {
                    'selection': {},
                    'condition': 'selection'
                }
            }
        }

    async def generate_rules(
        self,
        finding: SecurityFinding,
        parsed_data: Dict[str, Any]
    ) -> List[str]:
        rules = []

        rule_type = self._determine_rule_type(finding, parsed_data)
        if rule_type:
            rule = await self._build_rule(finding, parsed_data, rule_type)
            if rule:
                rules.append(rule)

        return rules

    def _determine_rule_type(
        self,
        finding: SecurityFinding,
        parsed_data: Dict[str, Any]
    ) -> Optional[str]:
        title_lower = finding.title.lower()
        description_lower = finding.description.lower()

        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['process', 'execution', 'command']):
            return 'process_creation'
        elif any(keyword in title_lower or keyword in description_lower
                 for keyword in ['network', 'connection', 'traffic']):
            return 'network_connection'
        elif any(keyword in title_lower or keyword in description_lower
                 for keyword in ['file', 'write', 'create', 'modify']):
            return 'file_event'
        elif any(keyword in title_lower or keyword in description_lower
                 for keyword in ['login', 'auth', 'credential', 'password']):
            return 'authentication'
        else:
            return 'process_creation'

    async def _build_rule(
        self,
        finding: SecurityFinding,
        parsed_data: Dict[str, Any],
        rule_type: str
    ) -> Optional[str]:
        try:
            template = self.rule_templates[rule_type].copy()

            rule = {
                'title': finding.title,
                'id': self._generate_rule_id(finding),
                'description': finding.description,
                'author': 'Security Agents',
                'date': datetime.now().strftime('%Y/%m/%d'),
                'tags': self._generate_tags(finding),
                'level': self._map_severity_to_level(finding.severity),
                'logsource': template['logsource'],
                'detection': self._build_detection_logic(finding, parsed_data, rule_type)
            }

            if finding.indicators:
                rule['references'] = finding.indicators

            falsepositives = self._generate_false_positives(finding, rule_type)
            if falsepositives:
                rule['falsepositives'] = falsepositives

            return yaml.dump(rule, default_flow_style=False, sort_keys=False)

        except Exception as e:
            return f"# Error generating Sigma rule: {str(e)}"

    def _generate_rule_id(self, finding: SecurityFinding) -> str:
        import uuid
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, finding.title + finding.description))

    def _generate_tags(self, finding: SecurityFinding) -> List[str]:
        tags = ['attack.discovery']

        title_lower = finding.title.lower()
        description_lower = finding.description.lower()

        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['execution', 'command', 'process']):
            tags.append('attack.execution')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['persistence', 'startup', 'service']):
            tags.append('attack.persistence')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['privilege', 'escalation', 'admin']):
            tags.append('attack.privilege_escalation')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['defense', 'evasion', 'bypass']):
            tags.append('attack.defense_evasion')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['credential', 'password', 'hash']):
            tags.append('attack.credential_access')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['discovery', 'reconnaissance', 'enum']):
            tags.append('attack.discovery')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['lateral', 'movement', 'remote']):
            tags.append('attack.lateral_movement')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['collection', 'data', 'steal']):
            tags.append('attack.collection')
        if any(keyword in title_lower or keyword in description_lower
               for keyword in ['exfiltration', 'transfer', 'upload']):
            tags.append('attack.exfiltration')

        return tags

    def _map_severity_to_level(self, severity: ThreatLevel) -> str:
        mapping = {
            ThreatLevel.LOW: 'low',
            ThreatLevel.MEDIUM: 'medium',
            ThreatLevel.HIGH: 'high',
            ThreatLevel.CRITICAL: 'critical'
        }
        return mapping.get(severity, 'medium')

    def _build_detection_logic(
        self,
        finding: SecurityFinding,
        parsed_data: Dict[str, Any],
        rule_type: str
    ) -> Dict[str, Any]:
        detection = {'condition': 'selection'}

        if rule_type == 'process_creation':
            selection = {}

            if 'CommandLine' in finding.evidence:
                selection['CommandLine|contains'] = finding.evidence['CommandLine']
            elif finding.indicators:
                for indicator in finding.indicators:
                    if any(keyword in indicator.lower() for keyword in ['cmd', 'powershell', 'exe']):
                        selection['CommandLine|contains'] = indicator
                        break

            if 'process_name' in parsed_data.get('indicators', {}):
                selection['Image|endswith'] = parsed_data['indicators']['process_name']

            detection['selection'] = selection

        elif rule_type == 'network_connection':
            selection = {}

            if 'destination_ip' in finding.evidence:
                selection['DestinationIp'] = finding.evidence['destination_ip']
            if 'destination_port' in finding.evidence:
                selection['DestinationPort'] = finding.evidence['destination_port']

            indicators = parsed_data.get('indicators', {})
            if 'ip_address' in indicators:
                selection['DestinationIp'] = indicators['ip_address']

            detection['selection'] = selection

        elif rule_type == 'file_event':
            selection = {}

            if 'file_path' in finding.evidence:
                selection['TargetFilename|contains'] = finding.evidence['file_path']
            elif finding.indicators:
                for indicator in finding.indicators:
                    if '\\' in indicator or '/' in indicator:
                        selection['TargetFilename|contains'] = indicator
                        break

            detection['selection'] = selection

        elif rule_type == 'authentication':
            selection = {}

            if 'username' in finding.evidence:
                selection['TargetUserName'] = finding.evidence['username']
            if 'logon_type' in finding.evidence:
                selection['LogonType'] = finding.evidence['logon_type']

            detection['selection'] = selection

        if not detection['selection']:
            detection['selection'] = {'EventID': '*'}

        return detection

    def _generate_false_positives(self, finding: SecurityFinding, rule_type: str) -> List[str]:
        false_positives = []

        if rule_type == 'process_creation':
            false_positives.extend([
                'Legitimate administrative activities',
                'Automated deployment scripts',
                'Software installation processes'
            ])
        elif rule_type == 'network_connection':
            false_positives.extend([
                'Legitimate application network traffic',
                'System updates and patches',
                'Cloud service connections'
            ])
        elif rule_type == 'file_event':
            false_positives.extend([
                'Legitimate software operations',
                'System maintenance tasks',
                'Backup operations'
            ])
        elif rule_type == 'authentication':
            false_positives.extend([
                'Legitimate user authentication',
                'Service account activities',
                'Automated system processes'
            ])

        return false_positives

    async def validate_rule(self, rule_yaml: str) -> Dict[str, Any]:
        try:
            rule = yaml.safe_load(rule_yaml)

            validation_result = {
                'valid': True,
                'errors': [],
                'warnings': []
            }

            required_fields = ['title', 'logsource', 'detection']
            for field in required_fields:
                if field not in rule:
                    validation_result['errors'].append(f"Missing required field: {field}")
                    validation_result['valid'] = False

            if 'detection' in rule:
                if 'condition' not in rule['detection']:
                    validation_result['errors'].append("Missing detection condition")
                    validation_result['valid'] = False

            if 'logsource' in rule:
                logsource = rule['logsource']
                if 'category' not in logsource and 'product' not in logsource:
                    validation_result['warnings'].append("Logsource should have category or product")

            return validation_result

        except yaml.YAMLError as e:
            return {
                'valid': False,
                'errors': [f"YAML parsing error: {str(e)}"],
                'warnings': []
            }

    async def optimize_rule(self, rule_yaml: str) -> str:
        try:
            rule = yaml.safe_load(rule_yaml)

            if 'detection' in rule and 'selection' in rule['detection']:
                selection = rule['detection']['selection']

                optimized_selection = {}
                for key, value in selection.items():
                    if isinstance(value, list) and len(value) == 1:
                        optimized_selection[key] = value[0]
                    else:
                        optimized_selection[key] = value

                rule['detection']['selection'] = optimized_selection

            return yaml.dump(rule, default_flow_style=False, sort_keys=False)

        except Exception:
            return rule_yaml