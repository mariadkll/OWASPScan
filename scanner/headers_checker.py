from urllib.parse import urlparse

import httpx

from scanner.models import Finding
from scanner.rules import create_finding


TIMEOUT = 5

# Cache-Control is checked only for paths that may return
# private or user-specific information.
SENSITIVE_PATH_MARKERS = [
    "/account",
    "/profile",
    "/api/me",
    "/admin",
    "/payment",
    "/checkout",
    "/billing"
]


def normalize_headers(headers: httpx.Headers) -> dict:

    normalized_headers = {}

    for name, value in headers.items():
        normalized_headers[name.lower()] = value.strip()

    return normalized_headers


def is_https_url(url: str) -> bool:

    parsed_url = urlparse(url)

    return parsed_url.scheme.lower() == "https"


def appears_sensitive(url: str) -> bool:
    """
    Estimates whether the URL may return private or user-specific data.

    This does not confirm that the response is sensitive. It is only
    used to decide whether Cache-Control should be evaluated.
    """

    path = urlparse(url).path.lower()

    return any(
        marker in path
        for marker in SENSITIVE_PATH_MARKERS
    )


def check_hsts(
    url: str,
    response_headers: dict
) -> list[Finding]:
    """
    Checks whether an HTTPS response includes HSTS.
    """

    findings = []

    # HSTS is relevant only when the final URL uses HTTPS.
    if not is_https_url(url):
        return findings

    hsts_value = response_headers.get(
        "strict-transport-security"
    )

    if not hsts_value:
        findings.append(
            create_finding(
                rule_id="HDR-001",
                evidence=(
                    f"Tested URL: {url}. "
                    "The final response used HTTPS but did not include "
                    "the Strict-Transport-Security header."
                )
            )
        )

    return findings


def check_content_type_options(
    url: str,
    response_headers: dict
) -> list[Finding]:
    """
    Checks whether X-Content-Type-Options is present and set to nosniff.
    """

    findings = []

    header_value = response_headers.get(
        "x-content-type-options"
    )

    if not header_value:
        findings.append(
            create_finding(
                rule_id="HDR-002",
                evidence=(
                    f"Tested URL: {url}. "
                    "The response did not include the "
                    "X-Content-Type-Options header."
                )
            )
        )

    elif header_value.lower() != "nosniff":
        findings.append(
            create_finding(
                rule_id="HDR-003",
                evidence=(
                    f"Tested URL: {url}. "
                    "X-Content-Type-Options was set to "
                    f"'{header_value}' instead of 'nosniff'."
                )
            )
        )

    return findings


def check_content_type(
    url: str,
    response_headers: dict
) -> list[Finding]:
    """
    Checks whether the response declares its content type.
    """

    findings = []

    content_type = response_headers.get("content-type")

    if not content_type:
        findings.append(
            create_finding(
                rule_id="HDR-004",
                evidence=(
                    f"Tested URL: {url}. "
                    "The response did not include a Content-Type header."
                )
            )
        )

    return findings


def check_cache_control(
    url: str,
    response_headers: dict
) -> list[Finding]:
    """
    Checks caching protection only when the URL appears likely
    to return private or user-specific information.
    """

    findings = []

    # Do not report missing Cache-Control on normal public pages.
    if not appears_sensitive(url):
        return findings

    cache_control = response_headers.get(
        "cache-control",
        ""
    ).lower()

    protective_directives = [
        "no-store",
        "private"
    ]

    is_protected = any(
        directive in cache_control
        for directive in protective_directives
    )

    if not is_protected:
        findings.append(
            create_finding(
                rule_id="HDR-005",
                evidence=(
                    f"Tested URL: {url}. "
                    "The URL path suggests that the response may contain "
                    "private or user-specific information, but the "
                    "Cache-Control header did not include 'private' or "
                    f"'no-store'. Returned value: "
                    f"{cache_control or 'not present'}. "
                    "This is a possible issue and requires manual "
                    "verification."
                )
            )
        )

    return findings


def check_headers(url: str) -> list[Finding]:
    """
    Main security-header checker.

    Sends one request, follows redirects, checks the final response,
    and returns all generated findings.
    """

    findings = []

    try:
        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={
                "User-Agent": "OWASPScan/1.0",
                "Accept": "text/html,application/json,*/*"
            }
        ) as client:
            response = client.get(url)

        final_url = str(response.url)

        response_headers = normalize_headers(
            response.headers
        )

        findings.extend(
            check_hsts(
                final_url,
                response_headers
            )
        )

        findings.extend(
            check_content_type_options(
                final_url,
                response_headers
            )
        )

        findings.extend(
            check_content_type(
                final_url,
                response_headers
            )
        )

        findings.extend(
            check_cache_control(
                final_url,
                response_headers
            )
        )

    except httpx.HTTPError as error:
        findings.append(
            create_finding(
                rule_id="HDR-006",
                evidence=(
                    f"Tested URL: {url}. "
                    "The security-header check could not be completed. "
                    f"Error: {error}."
                )
            )
        )

    return findings