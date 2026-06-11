"""Active reconnaissance functions.

Directory busting, technology fingerprinting, and header analysis.
"""

import logging
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin

import httpx

from redteam_analyzer.core.models import Evidence, Finding, FindingType, Severity, Target
from redteam_analyzer.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# Common wordlist (bundled)
DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "common.txt"

# Security headers to check
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": Severity.MEDIUM,
        "description": "HTTP Strict Transport Security not set",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": Severity.MEDIUM,
        "description": "Content Security Policy not set",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": Severity.LOW,
        "description": "X-Frame-Options not set (clickjacking risk)",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options not set",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": Severity.INFO,
        "description": "X-XSS-Protection not set",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": Severity.INFO,
        "description": "Referrer-Policy not set",
    },
}


async def directory_bust(
    target: Target,
    wordlist_path: Optional[Path] = None,
    rate_limiter: Optional[RateLimiter] = None,
    extensions: Optional[List[str]] = None,
    timeout: int = 10,
) -> List[Finding]:
    """Perform directory busting against a target.

    Args:
        target: Target URL to bust
        wordlist_path: Path to wordlist file (uses default if None)
        rate_limiter: Rate limiter instance
        extensions: File extensions to try (e.g., [".php", ".html"])
        timeout: Request timeout per request

    Returns:
        List of findings for discovered paths
    """
    findings = []

    # Determine base URL
    base_url = target.url or f"http://{target.hostname}"
    if not base_url.endswith("/"):
        base_url += "/"

    # Load wordlist
    wl_path = wordlist_path or DEFAULT_WORDLIST
    if not wl_path.exists():
        logger.warning(f"Wordlist not found: {wl_path}")
        return findings

    words = wl_path.read_text().splitlines()
    words = [w.strip() for w in words if w.strip()]

    # Add extensions if provided
    if extensions:
        extended_words = []
        for word in words:
            extended_words.append(word)
            for ext in extensions:
                if not word.endswith(ext):
                    extended_words.append(f"{word}{ext}")
        words = extended_words

    # Domain for rate limiting
    domain = target.domain or target.primary

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        ) as client:
            for word in words:
                url = urljoin(base_url, word)

                # Rate limiting
                if rate_limiter:
                    await rate_limiter.acquire(domain)

                try:
                    response = await client.get(url)

                    # Skip 404s and common error codes
                    if response.status_code in (404, 403, 500, 502, 503):
                        continue

                    # Found something
                    findings.append(
                        Finding(
                            type=FindingType.PATH_FOUND,
                            severity=Severity.INFO,
                            location=url,
                            title=f"Path found: /{word}",
                            description=f"HTTP {response.status_code} response",
                            evidence=Evidence(
                                raw_output=f"Status: {response.status_code}",
                                structured_data={
                                    "status_code": response.status_code,
                                    "content_length": len(response.content),
                                    "content_type": response.headers.get("content-type", ""),
                                },
                                tool_name="recon/dirbust",
                            ),
                        )
                    )

                except httpx.RequestError:
                    continue

    except Exception as e:
        logger.error(f"Directory busting failed: {e}")

    return findings


async def tech_fingerprint(
    target: Target,
    timeout: int = 15,
) -> List[Finding]:
    """Perform technology fingerprinting using HTTP headers and response patterns.

    Args:
        target: Target URL to fingerprint
        timeout: Request timeout

    Returns:
        List of findings for detected technologies
    """
    findings = []

    # Determine base URL
    base_url = target.url or f"http://{target.hostname}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.get(base_url)

            # Check server header
            server = response.headers.get("server", "")
            if server:
                findings.append(
                    Finding(
                        type=FindingType.TECH_DETECTED,
                        severity=Severity.INFO,
                        location=base_url,
                        title=f"Server detected: {server}",
                        description=f"Server header reveals: {server}",
                        evidence=Evidence(
                            raw_output=server,
                            structured_data={"server": server},
                            tool_name="recon/fingerprint",
                        ),
                    )
                )

            # Check X-Powered-By
            powered_by = response.headers.get("x-powered-by", "")
            if powered_by:
                findings.append(
                    Finding(
                        type=FindingType.TECH_DETECTED,
                        severity=Severity.LOW,
                        location=base_url,
                        title=f"Technology revealed: {powered_by}",
                        description=f"X-Powered-By header reveals: {powered_by}",
                        evidence=Evidence(
                            raw_output=powered_by,
                            structured_data={"powered_by": powered_by},
                            tool_name="recon/fingerprint",
                        ),
                    )
                )

            # Check for common technology indicators in response body
            body = response.text.lower()
            tech_patterns = {
                "wordpress": "WordPress",
                "wp-content": "WordPress",
                "drupal": "Drupal",
                "joomla": "Joomla",
                "django": "Django",
                "flask": "Flask",
                "laravel": "Laravel",
                "rails": "Ruby on Rails",
                "angular": "Angular",
                "react": "React",
                "vue": "Vue.js",
                "jquery": "jQuery",
                "bootstrap": "Bootstrap",
            }

            for pattern, tech_name in tech_patterns.items():
                if pattern in body:
                    findings.append(
                        Finding(
                            type=FindingType.TECH_DETECTED,
                            severity=Severity.INFO,
                            location=base_url,
                            title=f"Technology detected: {tech_name}",
                            description=f"Detected {tech_name} in response body",
                            evidence=Evidence(
                                raw_output=pattern,
                                structured_data={"technology": tech_name},
                                tool_name="recon/fingerprint",
                            ),
                        )
                    )

    except httpx.RequestError as e:
        logger.warning(f"Fingerprint request failed: {e}")
    except Exception as e:
        logger.warning(f"Fingerprint error: {e}")

    return findings


async def header_analysis(
    target: Target,
    timeout: int = 15,
) -> List[Finding]:
    """Analyze HTTP headers for security issues.

    Args:
        target: Target URL to analyze
        timeout: Request timeout

    Returns:
        List of findings for missing security headers
    """
    findings = []

    # Determine base URL
    base_url = target.url or f"http://{target.hostname}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.get(base_url)
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            # Check for missing security headers
            for header_name, info in SECURITY_HEADERS.items():
                if header_name not in response_headers:
                    findings.append(
                        Finding(
                            type=FindingType.HEADER_MISSING,
                            severity=info["severity"],
                            location=base_url,
                            title=f"Missing: {info['name']}",
                            description=info["description"],
                            evidence=Evidence(
                                raw_output=f"Header '{header_name}' not found in response",
                                structured_data={"missing_header": header_name},
                                tool_name="recon/headers",
                            ),
                            remediation=f"Add '{header_name}' header to HTTP responses",
                        )
                    )

    except httpx.RequestError as e:
        logger.warning(f"Header analysis request failed: {e}")
    except Exception as e:
        logger.warning(f"Header analysis error: {e}")

    return findings
