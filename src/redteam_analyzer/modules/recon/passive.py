"""Passive reconnaissance functions.

Query public sources without contacting the target directly.
"""

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# crt.sh API endpoint
CRTSH_API = "https://crt.sh/?q={domain}&output=json"

# VirusTotal API endpoint
VT_API = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

# Shodan API endpoint
SHODAN_API = "https://api.shodan.io/dns/resolve/{hostname}?key={api_key}"


async def query_crtsh(domain: str, timeout: int = 30) -> List[str]:
    """Query crt.sh for certificate transparency subdomains.

    Args:
        domain: Target domain to search
        timeout: Request timeout in seconds

    Returns:
        List of unique subdomains found
    """
    url = CRTSH_API.format(domain=domain)
    subdomains = set()

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            response.raise_for_status()

            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh returns newline-separated names
                for subdomain in name.split("\n"):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain != domain:
                        # Remove wildcard prefix
                        if subdomain.startswith("*."):
                            subdomain = subdomain[2:]
                        subdomains.add(subdomain)

    except httpx.HTTPStatusError as e:
        logger.warning(f"crt.sh HTTP error for {domain}: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.warning(f"crt.sh request error for {domain}: {e}")
    except Exception as e:
        logger.warning(f"crt.sh unexpected error for {domain}: {e}")

    return sorted(subdomains)


async def query_virustotal(
    domain: str,
    api_key: str,
    timeout: int = 30,
) -> List[str]:
    """Query VirusTotal API for subdomains.

    Args:
        domain: Target domain
        api_key: VirusTotal API key
        timeout: Request timeout in seconds

    Returns:
        List of subdomains found
    """
    url = VT_API.format(domain=domain)
    headers = {"x-apikey": api_key}
    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()

            data = response.json()
            for item in data.get("data", []):
                subdomain = item.get("id", "")
                if subdomain and subdomain != domain:
                    subdomains.append(subdomain)

    except httpx.HTTPStatusError as e:
        logger.warning(f"VirusTotal HTTP error for {domain}: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.warning(f"VirusTotal request error for {domain}: {e}")
    except Exception as e:
        logger.warning(f"VirusTotal unexpected error for {domain}: {e}")

    return sorted(set(subdomains))


async def query_shodan(
    domain: str,
    api_key: str,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Query Shodan API for DNS resolution.

    Args:
        domain: Target domain
        api_key: Shodan API key
        timeout: Request timeout in seconds

    Returns:
        Dictionary mapping hostnames to IP addresses
    """
    url = SHODAN_API.format(hostname=domain, api_key=api_key)
    result = {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            result = response.json()

    except httpx.HTTPStatusError as e:
        logger.warning(f"Shodan HTTP error for {domain}: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.warning(f"Shodan request error for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Shodan unexpected error for {domain}: {e}")

    return result


async def resolve_dns(hostname: str) -> Dict[str, Any]:
    """Resolve DNS for a hostname using system resolver.

    Args:
        hostname: Hostname to resolve

    Returns:
        Dictionary with DNS resolution results
    """
    result = {
        "hostname": hostname,
        "ipv4": [],
        "ipv6": [],
        "aliases": [],
    }

    try:
        # Get all addresses
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            family, _, _, _, sockaddr = info
            ip = sockaddr[0]
            if family == socket.AF_INET:
                if ip not in result["ipv4"]:
                    result["ipv4"].append(ip)
            elif family == socket.AF_INET6:
                if ip not in result["ipv6"]:
                    result["ipv6"].append(ip)

        # Get canonical name and aliases
        try:
            canonical = socket.getfqdn(hostname)
            if canonical != hostname:
                result["canonical"] = canonical
        except Exception:
            pass

    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
    except Exception as e:
        logger.warning(f"DNS unexpected error for {hostname}: {e}")

    return result


async def passive_recon(
    domain: str,
    vt_api_key: Optional[str] = None,
    shodan_api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Run full passive reconnaissance against a domain.

    Args:
        domain: Target domain
        vt_api_key: Optional VirusTotal API key
        shodan_api_key: Optional Shodan API key

    Returns:
        Dictionary with all passive recon results
    """
    async def _empty_list():
        return []

    async def _empty_dict():
        return {}

    tasks = [
        query_crtsh(domain),
        resolve_dns(domain),
    ]

    if vt_api_key:
        tasks.append(query_virustotal(domain, vt_api_key))
    else:
        tasks.append(_empty_list())

    if shodan_api_key:
        tasks.append(query_shodan(domain, shodan_api_key))
    else:
        tasks.append(_empty_dict())

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results, handling exceptions
    crtsh_results = results[0] if isinstance(results[0], list) else []
    dns_results = results[1] if isinstance(results[1], dict) else {}
    vt_results = results[2] if isinstance(results[2], list) else []
    shodan_results = results[3] if isinstance(results[3], dict) else {}

    # Merge all subdomains
    all_subdomains = set(crtsh_results + vt_results)

    return {
        "domain": domain,
        "subdomains": sorted(all_subdomains),
        "dns": dns_results,
        "virustotal": vt_results,
        "shodan": shodan_results,
        "sources": {
            "crtsh": len(crtsh_results),
            "virustotal": len(vt_results),
            "shodan": bool(shodan_results),
        },
    }
