"""Scope validation for target whitelisting.

Validates that targets are within authorized scope before any network calls.
"""

from ipaddress import ip_address, ip_network
from typing import Optional
from urllib.parse import urlparse

from redteam_analyzer.core.models import ScopeConfig, Target


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Target '{target}' is out of scope: {reason}")


class ScopeValidator:
    """Validates targets against configured scope rules."""

    def __init__(self, config: ScopeConfig):
        self.config = config
        self._compiled_networks = self._compile_networks()

    def _compile_networks(self) -> list:
        """Pre-compile CIDR networks for efficient matching."""
        networks = []
        for cidr in self.config.allowed_cidrs:
            try:
                networks.append(ip_network(cidr, strict=False))
            except ValueError:
                continue
        return networks

    def validate(self, target: Target) -> None:
        """Validate that target is within scope. Raises ScopeError if not.

        Args:
            target: The target to validate

        Raises:
            ScopeError: If target is outside authorized scope
        """
        # Check IP/CIDR scope
        if target.ip:
            self._validate_ip(target.ip)

        # Check domain scope
        domain = target.domain
        if domain:
            self._validate_domain(domain)

        # Check URL scope
        if target.url:
            self._validate_url(target.url)

        # Check CIDR scope
        if target.cidr:
            self._validate_cidr(target.cidr)

    def _validate_ip(self, ip: str) -> None:
        """Validate an IP address is within allowed CIDRs."""
        if not self._compiled_networks:
            return  # No CIDR restrictions

        try:
            addr = ip_address(ip)
        except ValueError:
            raise ScopeError(ip, f"Invalid IP address: {ip}")

        for network in self._compiled_networks:
            if addr in network:
                return

        raise ScopeError(ip, f"IP {ip} not in any allowed CIDR range")

    def _validate_domain(self, domain: str) -> None:
        """Validate a domain is in the allowlist."""
        if not self.config.allowed_domains:
            return  # No domain restrictions

        # Check exact match
        if domain in self.config.allowed_domains:
            return

        # Check wildcard match (e.g., "*.example.com")
        for allowed in self.config.allowed_domains:
            if allowed.startswith("*."):
                allowed_base = allowed[2:]
                # Wildcard must match a subdomain, not the base domain itself
                # "*.example.com" matches "sub.example.com" but NOT "example.com"
                if domain.endswith(allowed_base) and domain != allowed_base:
                    return

        raise ScopeError(domain, f"Domain {domain} not in allowlist")

    def _validate_url(self, url: str) -> None:
        """Validate a URL's host is within scope."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname:
                self._validate_domain(hostname)
        except Exception as e:
            if isinstance(e, ScopeError):
                raise
            raise ScopeError(url, f"Invalid URL: {url}")

    def _validate_cidr(self, cidr: str) -> None:
        """Validate a CIDR range is within allowed scope."""
        try:
            target_network = ip_network(cidr, strict=False)
        except ValueError:
            raise ScopeError(cidr, f"Invalid CIDR: {cidr}")

        for allowed_network in self._compiled_networks:
            if target_network.subnet_of(allowed_network):
                return

        raise ScopeError(cidr, f"CIDR {cidr} not within any allowed range")

    def is_in_scope(self, target: Target) -> bool:
        """Check if target is in scope without raising.

        Args:
            target: The target to check

        Returns:
            True if in scope, False otherwise
        """
        try:
            self.validate(target)
            return True
        except ScopeError:
            return False
