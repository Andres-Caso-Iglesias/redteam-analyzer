"""Tests for reconnaissance plugin."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from redteam_analyzer.core.models import ScanConfig, ScanResult, ScopeConfig, Target
from redteam_analyzer.modules.recon.passive import (
    query_crtsh,
    query_virustotal,
    query_shodan,
    resolve_dns,
    passive_recon,
)
from redteam_analyzer.modules.recon.active import (
    directory_bust,
    tech_fingerprint,
    header_analysis,
)
from redteam_analyzer.modules.recon.plugin import ReconPlugin


@pytest.fixture
def target():
    return Target(hostname="example.com", url="https://example.com")


@pytest.fixture
def config():
    return ScanConfig(
        scope=ScopeConfig(allowed_domains=["example.com"]),
    )


class TestPassiveRecon:
    @pytest.mark.asyncio
    async def test_crtsh_query(self):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com\nsub3.example.com"},
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await query_crtsh("example.com")

            assert "sub1.example.com" in result
            assert "sub2.example.com" in result
            assert "sub3.example.com" in result

    @pytest.mark.asyncio
    async def test_crtsh_wildcard_removal(self):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name_value": "*.example.com"},
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await query_crtsh("example.com")

            # Wildcard should be removed
            assert "*.example.com" not in result
            assert "example.com" in result

    @pytest.mark.asyncio
    async def test_virustotal_query(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"id": "sub1.example.com"},
                {"id": "sub2.example.com"},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await query_virustotal("example.com", "test-api-key")

            assert "sub1.example.com" in result
            assert "sub2.example.com" in result

    @pytest.mark.asyncio
    async def test_shodan_query(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "example.com": "93.184.216.34",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await query_shodan("example.com", "test-api-key")

            assert result.get("example.com") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_dns_resolution(self):
        result = await resolve_dns("localhost")

        assert result["hostname"] == "localhost"
        assert len(result["ipv4"]) > 0

    @pytest.mark.asyncio
    async def test_passive_recon_full(self):
        with patch("redteam_analyzer.modules.recon.passive.query_crtsh") as mock_crtsh:
            mock_crtsh.return_value = ["sub1.example.com", "sub2.example.com"]

            with patch("redteam_analyzer.modules.recon.passive.resolve_dns") as mock_dns:
                mock_dns.return_value = {"ipv4": ["93.184.216.34"]}

                result = await passive_recon("example.com")

                assert result["domain"] == "example.com"
                assert "sub1.example.com" in result["subdomains"]
                assert "sub2.example.com" in result["subdomains"]


class TestActiveRecon:
    @pytest.mark.asyncio
    async def test_header_analysis(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "server": "nginx/1.18.0",
            "content-type": "text/html",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            findings = await header_analysis(Target(url="https://example.com"))

            # Should find missing security headers
            assert len(findings) > 0
            assert any("Missing" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_tech_fingerprint(self):
        mock_response = MagicMock()
        mock_response.headers = {"server": "nginx/1.18.0"}
        mock_response.text = '<html><div class="wp-content">WordPress</div></html>'

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            findings = await tech_fingerprint(Target(url="https://example.com"))

            # Should detect server and WordPress
            assert len(findings) >= 1
            assert any("nginx" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_directory_bust_with_mock(self):
        # Mock response for found path
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Found"
        mock_response.headers = {"content-type": "text/html"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            # Use a small test wordlist
            from pathlib import Path
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("admin\nlogin\ntest\n")
                wordlist_path = Path(f.name)

            try:
                findings = await directory_bust(
                    target=Target(url="https://example.com"),
                    wordlist_path=wordlist_path,
                )

                # Should find paths (all 3 words return 200 in our mock)
                assert len(findings) == 3
                assert all(f.type.value == "path_found" for f in findings)
            finally:
                wordlist_path.unlink()


class TestReconPlugin:
    def test_plugin_init(self):
        plugin = ReconPlugin()
        assert plugin.name == "recon"
        assert plugin.requires_auth is False

    def test_validate_dependencies(self):
        plugin = ReconPlugin()
        assert plugin.validate_dependencies() is True

    @pytest.mark.asyncio
    async def test_plugin_run_passive_only(self, target, config):
        config.passive_only = True
        plugin = ReconPlugin()

        with patch("redteam_analyzer.modules.recon.plugin.passive_recon") as mock_recon:
            mock_recon.return_value = {
                "subdomains": ["sub.example.com"],
                "dns": {"ipv4": ["93.184.216.34"]},
                "sources": {"crtsh": 1, "virustotal": 0, "shodan": False},
            }

            result = await plugin.run(target, config)

            assert isinstance(result, ScanResult)
            assert len(result.metadata) == 1
            assert result.metadata[0].plugin_name == "recon"

    @pytest.mark.asyncio
    async def test_plugin_run_dry_run(self, target, config):
        config.dry_run = True
        plugin = ReconPlugin()

        result = await plugin.run(target, config)

        assert isinstance(result, ScanResult)
        assert result.metadata[0].dry_run is True
        # Should not make network calls in dry-run
