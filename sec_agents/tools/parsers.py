import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
import base64


class LogParser:
    def __init__(self):
        self.patterns = {
            'timestamp': r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'user_agent': r'User-Agent: ([^\n\r]*)',
            'http_status': r'\s([1-5]\d{2})\s',
            'url': r'(https?://[^\s]+)',
            'file_path': r'([A-Za-z]:\\[^\s]*|/[^\s]*)',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
        }

    async def parse(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(data.get('raw_log'), str):
            return await self._parse_text_log(data['raw_log'])
        elif isinstance(data, dict) and 'logs' in data:
            return await self._parse_structured_logs(data['logs'])
        else:
            return await self._extract_indicators(str(data))

    async def _parse_text_log(self, log_text: str) -> Dict[str, Any]:
        parsed = {
            'log_type': 'text',
            'indicators': {},
            'events': [],
            'metadata': {}
        }

        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, log_text)
            if matches:
                parsed['indicators'][name] = list(set(matches))

        lines = log_text.split('\n')
        for i, line in enumerate(lines[:100]):
            if any(keyword in line.lower() for keyword in
                   ['error', 'fail', 'attack', 'breach', 'unauthorized', 'suspicious']):
                parsed['events'].append({
                    'line_number': i + 1,
                    'content': line.strip(),
                    'severity': self._assess_severity(line)
                })

        parsed['metadata'] = {
            'total_lines': len(lines),
            'suspicious_lines': len(parsed['events']),
            'parsed_at': datetime.now().isoformat()
        }

        return parsed

    async def _parse_structured_logs(self, logs: List[Dict]) -> Dict[str, Any]:
        parsed = {
            'log_type': 'structured',
            'indicators': {},
            'events': [],
            'metadata': {}
        }

        all_ips = set()
        all_users = set()
        error_events = []

        for log_entry in logs:
            if isinstance(log_entry, dict):
                if 'src_ip' in log_entry:
                    all_ips.add(log_entry['src_ip'])
                if 'user' in log_entry:
                    all_users.add(log_entry['user'])
                if log_entry.get('level') in ['ERROR', 'CRITICAL', 'ALERT']:
                    error_events.append(log_entry)

        parsed['indicators']['ip_addresses'] = list(all_ips)
        parsed['indicators']['users'] = list(all_users)
        parsed['events'] = error_events
        parsed['metadata'] = {
            'total_logs': len(logs),
            'error_count': len(error_events),
            'unique_ips': len(all_ips),
            'unique_users': len(all_users)
        }

        return parsed

    async def _extract_indicators(self, text: str) -> Dict[str, Any]:
        parsed = {
            'log_type': 'generic',
            'indicators': {},
            'events': [],
            'metadata': {}
        }

        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                parsed['indicators'][name] = list(set(matches))

        return parsed

    def _assess_severity(self, line: str) -> str:
        line_lower = line.lower()
        if any(word in line_lower for word in ['critical', 'emergency', 'breach']):
            return 'high'
        elif any(word in line_lower for word in ['error', 'fail', 'attack']):
            return 'medium'
        else:
            return 'low'


class NetworkParser:
    def __init__(self):
        self.suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5985, 5986]
        self.private_ranges = [
            (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
            (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
            (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
        ]

    async def parse(self, data: Dict[str, Any]) -> Dict[str, Any]:
        parsed = {
            'network_type': 'traffic',
            'connections': [],
            'suspicious_activity': [],
            'statistics': {},
            'metadata': {}
        }

        if 'netflow' in data:
            parsed.update(await self._parse_netflow(data['netflow']))
        elif 'pcap' in data:
            parsed.update(await self._parse_pcap_summary(data['pcap']))
        elif 'connections' in data:
            parsed.update(await self._analyze_connections(data['connections']))

        return parsed

    async def _parse_netflow(self, netflow_data: List[Dict]) -> Dict[str, Any]:
        connections = []
        suspicious = []
        port_stats = {}

        for flow in netflow_data:
            conn = {
                'src_ip': flow.get('src_ip'),
                'dst_ip': flow.get('dst_ip'),
                'src_port': flow.get('src_port'),
                'dst_port': flow.get('dst_port'),
                'protocol': flow.get('protocol'),
                'bytes': flow.get('bytes', 0),
                'duration': flow.get('duration', 0)
            }
            connections.append(conn)

            if conn['dst_port'] in self.suspicious_ports:
                suspicious.append({
                    'type': 'suspicious_port',
                    'connection': conn,
                    'reason': f"Connection to suspicious port {conn['dst_port']}"
                })

            port = conn['dst_port']
            port_stats[port] = port_stats.get(port, 0) + 1

        return {
            'connections': connections,
            'suspicious_activity': suspicious,
            'statistics': {
                'total_flows': len(netflow_data),
                'top_ports': sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            }
        }

    async def _parse_pcap_summary(self, pcap_data: Dict) -> Dict[str, Any]:
        return {
            'connections': pcap_data.get('conversations', []),
            'suspicious_activity': [],
            'statistics': pcap_data.get('stats', {}),
            'protocols': pcap_data.get('protocols', {})
        }

    async def _analyze_connections(self, connections: List[Dict]) -> Dict[str, Any]:
        suspicious = []
        stats = {'internal_to_external': 0, 'external_to_internal': 0}

        for conn in connections:
            src_ip = conn.get('src_ip')
            dst_ip = conn.get('dst_ip')

            if src_ip and dst_ip:
                src_internal = self._is_private_ip(src_ip)
                dst_internal = self._is_private_ip(dst_ip)

                if src_internal and not dst_internal:
                    stats['internal_to_external'] += 1
                elif not src_internal and dst_internal:
                    stats['external_to_internal'] += 1

        return {
            'connections': connections,
            'suspicious_activity': suspicious,
            'statistics': stats
        }

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
            return any(start <= ip_int <= end for start, end in self.private_ranges)
        except:
            return False


class FileParser:
    def __init__(self):
        self.suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js']
        self.archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']

    async def parse(self, data: Dict[str, Any]) -> Dict[str, Any]:
        parsed = {
            'file_type': 'unknown',
            'metadata': {},
            'indicators': {},
            'suspicious_features': [],
            'analysis_results': {}
        }

        if 'file_path' in data:
            parsed.update(await self._analyze_file_path(data['file_path']))
        elif 'file_hash' in data:
            parsed.update(await self._analyze_file_hash(data['file_hash']))
        elif 'file_content' in data:
            parsed.update(await self._analyze_file_content(data['file_content']))
        elif 'binary_data' in data:
            parsed.update(await self._analyze_binary_data(data['binary_data']))

        return parsed

    async def _analyze_file_path(self, file_path: str) -> Dict[str, Any]:
        analysis = {
            'file_type': 'path_analysis',
            'metadata': {
                'file_path': file_path,
                'file_name': file_path.split('/')[-1] if '/' in file_path else file_path.split('\\')[-1],
                'extension': '.' + file_path.split('.')[-1] if '.' in file_path else ''
            },
            'suspicious_features': []
        }

        file_name = analysis['metadata']['file_name']
        extension = analysis['metadata']['extension']

        if extension.lower() in self.suspicious_extensions:
            analysis['suspicious_features'].append({
                'type': 'suspicious_extension',
                'description': f"File has suspicious extension: {extension}"
            })

        if any(keyword in file_name.lower() for keyword in
               ['temp', 'tmp', 'cache', 'system32', 'appdata']):
            analysis['suspicious_features'].append({
                'type': 'suspicious_location',
                'description': f"File in suspicious location: {file_path}"
            })

        return analysis

    async def _analyze_file_hash(self, file_hash: str) -> Dict[str, Any]:
        analysis = {
            'file_type': 'hash_analysis',
            'metadata': {
                'hash_value': file_hash,
                'hash_type': self._determine_hash_type(file_hash)
            },
            'indicators': {
                'hash': file_hash
            }
        }

        return analysis

    async def _analyze_file_content(self, content: str) -> Dict[str, Any]:
        analysis = {
            'file_type': 'content_analysis',
            'metadata': {
                'content_length': len(content),
                'content_hash': hashlib.sha256(content.encode()).hexdigest()
            },
            'suspicious_features': []
        }

        suspicious_patterns = [
            r'eval\(',
            r'exec\(',
            r'powershell',
            r'cmd\.exe',
            r'rundll32',
            r'regsvr32',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis['suspicious_features'].append({
                    'type': 'suspicious_pattern',
                    'description': f"Found suspicious pattern: {pattern}"
                })

        return analysis

    async def _analyze_binary_data(self, binary_data: str) -> Dict[str, Any]:
        try:
            data = base64.b64decode(binary_data)
            analysis = {
                'file_type': 'binary_analysis',
                'metadata': {
                    'size_bytes': len(data),
                    'entropy': self._calculate_entropy(data)
                },
                'suspicious_features': []
            }

            if analysis['metadata']['entropy'] > 7.5:
                analysis['suspicious_features'].append({
                    'type': 'high_entropy',
                    'description': f"High entropy detected: {analysis['metadata']['entropy']:.2f}"
                })

            return analysis
        except:
            return {
                'file_type': 'binary_analysis_failed',
                'metadata': {},
                'suspicious_features': [{'type': 'parse_error', 'description': 'Failed to decode binary data'}]
            }

    def _determine_hash_type(self, hash_value: str) -> str:
        length = len(hash_value)
        if length == 32:
            return 'MD5'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256'
        else:
            return 'unknown'

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * (probability.bit_length() - 1)

        return entropy