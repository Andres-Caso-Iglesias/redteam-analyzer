"""Tests for scope validation."""

import pytest

from redteam_analyzer.core.models import ScopeConfig, Target
from redteam_analyzer.core.scope import ScopeError, ScopeValidator


class TestScopeValidator:
    def test_ip_in_scope(self):
        config = ScopeConfig(allowed_cidrs=["192.168.0.0/16"])
        validator = ScopeValidator(config)
        target = Target(ip="192.168.1.100")
        # Should not raise
        validator.validate(target)

    def test_ip_out_of_scope(self):
        config = ScopeConfig(allowed_cidrs=["192.168.0.0/16"])
        validator = ScopeValidator(config)
        target = Target(ip="10.0.0.1")
        with pytest.raises(ScopeError) as exc_info:
            validator.validate(target)
        assert "10.0.0.1" in str(exc_info.value)

    def test_localhost_in_scope(self):
        config = ScopeConfig(allowed_cidrs=["127.0.0.0/8"])
        validator = ScopeValidator(config)
        target = Target(ip="127.0.0.1")
        validator.validate(target)

    def test_multiple_cidrs(self):
        config = ScopeConfig(allowed_cidrs=["127.0.0.0/8", "192.168.0.0/16"])
        validator = ScopeValidator(config)
        assert validator.is_in_scope(Target(ip="127.0.0.1"))
        assert validator.is_in_scope(Target(ip="192.168.1.1"))
        assert not validator.is_in_scope(Target(ip="10.0.0.1"))

    def test_domain_in_scope(self):
        config = ScopeConfig(allowed_domains=["example.com"])
        validator = ScopeValidator(config)
        target = Target(hostname="example.com")
        validator.validate(target)

    def test_domain_out_of_scope(self):
        config = ScopeConfig(allowed_domains=["example.com"])
        validator = ScopeValidator(config)
        target = Target(hostname="evil.com")
        with pytest.raises(ScopeError):
            validator.validate(target)

    def test_wildcard_domain(self):
        config = ScopeConfig(allowed_domains=["*.example.com"])
        validator = ScopeValidator(config)
        assert validator.is_in_scope(Target(hostname="sub.example.com"))
        assert validator.is_in_scope(Target(hostname="deep.sub.example.com"))
        # *.example.com does NOT match example.com (wildcards require subdomain)
        assert not validator.is_in_scope(Target(hostname="example.com"))

    def test_url_validation(self):
        config = ScopeConfig(allowed_domains=["example.com"])
        validator = ScopeValidator(config)
        assert validator.is_in_scope(Target(url="https://example.com/path"))
        assert not validator.is_in_scope(Target(url="https://evil.com/path"))

    def test_no_restrictions(self):
        config = ScopeConfig()
        validator = ScopeValidator(config)
        # Should allow anything when no restrictions
        assert validator.is_in_scope(Target(ip="1.2.3.4"))
        assert validator.is_in_scope(Target(hostname="anywhere.com"))

    def test_is_in_scope_method(self):
        config = ScopeConfig(allowed_cidrs=["192.168.0.0/16"])
        validator = ScopeValidator(config)
        assert validator.is_in_scope(Target(ip="192.168.1.1"))
        assert not validator.is_in_scope(Target(ip="10.0.0.1"))

    def test_scope_error_attributes(self):
        config = ScopeConfig(allowed_cidrs=["192.168.0.0/16"])
        validator = ScopeValidator(config)
        target = Target(ip="10.0.0.1")
        with pytest.raises(ScopeError) as exc_info:
            validator.validate(target)
        assert exc_info.value.target == "10.0.0.1"
        assert "not in any allowed cidr" in exc_info.value.reason.lower()
