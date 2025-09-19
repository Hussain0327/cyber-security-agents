import pytest
import asyncio
import os
import logging
from pathlib import Path

pytest_plugins = ['pytest_asyncio']


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment and configure logging."""
    os.environ.setdefault("TESTING", "true")
    os.environ.setdefault("LOG_LEVEL", "DEBUG")

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    test_data_dir = Path(__file__).parent.parent / "data"
    if not test_data_dir.exists():
        pytest.skip("Test data directory not found")

    yield

    logging.shutdown()


@pytest.fixture
def mock_provider():
    """Mock security provider for testing."""
    from unittest.mock import AsyncMock
    from ..core.models import AnalysisResult, SecurityFinding, ThreatLevel

    provider = AsyncMock()
    provider.analyze_security_data.return_value = AnalysisResult(
        findings=[
            SecurityFinding(
                title="Test Finding",
                description="Test security finding for evaluation",
                severity=ThreatLevel.MEDIUM,
                confidence=0.8,
                indicators=["test_indicator"],
                evidence={"test": "evidence"}
            )
        ],
        recommendations=["Test recommendation"],
        confidence_score=0.8,
        threat_level=ThreatLevel.MEDIUM,
        mitre_techniques=["T1059"],
        sigma_rules=["test_rule"]
    )
    return provider


@pytest.fixture
def sample_log_data():
    """Sample log data for testing."""
    return {
        "raw_log": "2024-01-15 10:30:00 [INFO] EventID=4688 ProcessName=powershell.exe CommandLine=\"powershell.exe -EncodedCommand test\"",
        "logs": [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "event_id": 4688,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand test",
                "user": "test_user"
            }
        ]
    }


@pytest.fixture
def sample_network_data():
    """Sample network data for testing."""
    return {
        "connections": [
            {
                "src_ip": "10.10.10.55",
                "dst_ip": "185.243.112.89",
                "dst_port": 443,
                "protocol": "TCP",
                "bytes": 2048,
                "timestamp": "2024-01-15T10:30:00Z"
            }
        ],
        "dns_queries": [
            {
                "query": "malicious-domain.com",
                "response": "185.243.112.89",
                "timestamp": "2024-01-15T10:29:55Z"
            }
        ]
    }


@pytest.fixture
def sample_file_data():
    """Sample file data for testing."""
    return {
        "file_path": "C:\\Windows\\Temp\\malware.exe",
        "file_hash": "a1b2c3d4e5f6789012345678901234567890abcdef",
        "file_content": "test malware content with suspicious patterns",
        "binary_data": "VGVzdCBiaW5hcnkgZGF0YQ=="
    }


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "api: mark test as API test"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location."""
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        if "test_performance" in item.name:
            item.add_marker(pytest.mark.slow)