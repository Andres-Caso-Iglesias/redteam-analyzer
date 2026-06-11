"""Tests for port scanning plugin."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from redteam_analyzer.core.models import ScanConfig, ScanResult, ScopeConfig, Target
from redteam_analyzer.modules.scan.nmap_wrapper import (
    parse_nmap_xml,
    extract_open_ports,
)
from redteam_analyzer.modules.scan.masscan_wrapper import (
    parse_masscan_json,
    extract_open_ports as masscan_extract,
)
from redteam_analyzer.modules.scan.plugin import ScanPlugin
from redteam_analyzer.utils.external_tools import ToolNotFoundError


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -O 192.168.1.1" start="1234567890">
  <scaninfo type="syn" protocol="tcp"/>
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
    </os>
  </host>
</nmaprun>"""

SAMPLE_MASSCAN_JSON = """[{"ip":"192.168.1.1","ports":[{"port":80,"proto":"tcp","status":"open","service":{"name":"http"}}]}]"""


class TestNmapWrapper:
    def test_parse_nmap_xml(self):
        results = parse_nmap_xml(SAMPLE_NMAP_XML)

        assert "hosts" in results
        assert len(results["hosts"]) == 1

        host = results["hosts"][0]
        assert host["ip"] == "192.168.1.1"
        assert host["hostname"] == "example.com"
        assert len(host["ports"]) == 3

    def test_extract_open_ports(self):
        results = parse_nmap_xml(SAMPLE_NMAP_XML)
        open_ports = extract_open_ports(results)

        assert len(open_ports) == 3
        assert any(p["port"] == "80" for p in open_ports)
        assert any(p["port"] == "443" for p in open_ports)
        assert any(p["port"] == "22" for p in open_ports)

    def test_parse_nmap_xml_invalid(self):
        results = parse_nmap_xml("not xml")
        assert "error" in results

    def test_parse_nmap_xml_empty(self):
        results = parse_nmap_xml("<nmaprun></nmaprun>")
        assert results["hosts"] == []


class TestMasscanWrapper:
    def test_parse_masscan_json(self):
        results = parse_masscan_json(SAMPLE_MASSCAN_JSON)

        assert "hosts" in results
        assert len(results["hosts"]) == 1

        host = results["hosts"][0]
        assert host["ip"] == "192.168.1.1"
        assert len(host["ports"]) == 1

    def test_extract_open_ports(self):
        results = parse_masscan_json(SAMPLE_MASSCAN_JSON)
        open_ports = masscan_extract(results)

        assert len(open_ports) == 1
        assert open_ports[0]["port"] == "80"

    def test_parse_masscan_json_invalid(self):
        results = parse_masscan_json("not json")
        assert "error" in results


class TestScanPlugin:
    def test_plugin_init(self):
        plugin = ScanPlugin()
        assert plugin.name == "scan"
        assert plugin.requires_auth is False

    def test_validate_dependencies_no_tools(self):
        plugin = ScanPlugin()
        with patch("redteam_analyzer.modules.scan.plugin.check_tool_installed") as mock_check:
            mock_check.return_value = False
            assert plugin.validate_dependencies() is False

    def test_validate_dependencies_with_nmap(self):
        plugin = ScanPlugin()
        with patch("redteam_analyzer.modules.scan.plugin.check_tool_installed") as mock_check:
            mock_check.side_effect = lambda x: x == "nmap"
            assert plugin.validate_dependencies() is True

    @pytest.mark.asyncio
    async def test_plugin_run_nmap(self):
        plugin = ScanPlugin()
        target = Target(ip="192.168.1.1")
        config = ScanConfig(scope=ScopeConfig())

        with patch("redteam_analyzer.modules.scan.plugin.run_nmap") as mock_nmap:
            mock_nmap.return_value = {
                "hosts": [
                    {
                        "ip": "192.168.1.1",
                        "ports": [
                            {
                                "port": "80",
                                "protocol": "tcp",
                                "state": "open",
                                "service": {
                                    "name": "http",
                                    "product": "nginx",
                                    "version": "1.18.0",
                                },
                            }
                        ],
                    }
                ]
            }

            result = await plugin.run(target, config)

            assert isinstance(result, ScanResult)
            assert len(result.findings) == 2  # PORT_OPEN + SERVICE_DETECTED
            assert result.findings[0].type.value == "port_open"

    @pytest.mark.asyncio
    async def test_plugin_run_tool_not_found(self):
        plugin = ScanPlugin()
        target = Target(ip="192.168.1.1")
        config = ScanConfig(scope=ScopeConfig())

        with patch("redteam_analyzer.modules.scan.plugin.run_nmap") as mock_nmap:
            mock_nmap.side_effect = ToolNotFoundError("nmap")

            result = await plugin.run(target, config)

            assert len(result.errors) == 1
            assert "not installed" in result.errors[0]

    @pytest.mark.asyncio
    async def test_plugin_run_masscan_backend(self):
        plugin = ScanPlugin()
        target = Target(ip="192.168.1.0/24")
        config = ScanConfig(scope=ScopeConfig())
        config.scan_backend = "masscan"

        with patch("redteam_analyzer.modules.scan.plugin.check_tool_installed") as mock_check:
            mock_check.return_value = True

            with patch("redteam_analyzer.modules.scan.plugin.run_masscan") as mock_masscan:
                mock_masscan.return_value = {
                    "hosts": [
                        {
                            "ip": "192.168.1.1",
                            "ports": [
                                {
                                    "port": "80",
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": "http",
                                }
                            ],
                        }
                    ]
                }

                result = await plugin.run(target, config)

                assert isinstance(result, ScanResult)
                mock_masscan.assert_called_once()
