import re
from html.parser import HTMLParser

import httpx

from scanner.models import Finding
from scanner.rules import create_finding


HEADERS = {
    "User-Agent": "OWASPScan/1.0",
    "Accept": "text/html,application/json,*/*"
}

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator"
]

MAX_HTML_LENGTH = 100_000

VERSION_PATTERN = re.compile(
    r"\b\d+(?:\.\d+){1,3}\b"
)


class GeneratorMetaParser(HTMLParser):
    """
    Extracts the value of an HTML meta generator tag.
    """

    def __init__(self) -> None:
        super().__init__()
        self.generator_values = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str]]
    ) -> None:
        if tag.lower() != "meta":
            return

        attributes = {
            str(name).lower(): value
            for name, value in attrs
            if name
        }

        meta_name = attributes.get(
            "name",
            ""
        ).lower()

        content = attributes.get(
            "content",
            ""
        ).strip()

        if (
            meta_name == "generator"
            and content
        ):
            self.generator_values.append(
                content
            )


def contains_version(value: str) -> bool:
    """
    Returns True when an explicit version number appears
    in the disclosed value.
    """

    return bool(
        VERSION_PATTERN.search(
            str(value)
        )
    )


def create_disclosure_finding(
    source: str,
    field_name: str,
    value: str,
    tested_url: str
) -> Finding:
    """
    Creates either a version-disclosure finding or a general
    technology-disclosure finding.
    """

    version_found = contains_version(
        value
    )

    rule_id = (
        "TECH-001"
        if version_found
        else "TECH-002"
    )

    version_statement = (
        "An explicit version number was detected."
        if version_found
        else "No explicit version number was detected."
    )

    evidence = (
        f"Tested URL: {tested_url}. "
        f"Disclosure source: {source}. "
        f"Field: {field_name}. "
        f"Returned value: {value}. "
        f"{version_statement}"
    )

    return create_finding(
        rule_id=rule_id,
        evidence=evidence
    )


def extract_header_disclosures(
    response: httpx.Response,
    tested_url: str
) -> list[Finding]:
    """
    Checks selected HTTP response headers for explicitly
    disclosed technologies.
    """

    findings = []

    for header_name in DISCLOSURE_HEADERS:
        header_value = response.headers.get(
            header_name
        )

        if not header_value:
            continue

        findings.append(
            create_disclosure_finding(
                source="HTTP response header",
                field_name=header_name,
                value=header_value.strip(),
                tested_url=tested_url
            )
        )

    return findings


def extract_generator_disclosures(
    response: httpx.Response,
    tested_url: str
) -> list[Finding]:
    """
    Checks an HTML response for meta generator disclosures.
    """

    content_type = response.headers.get(
        "content-type",
        ""
    ).lower()

    if "text/html" not in content_type:
        return []

    parser = GeneratorMetaParser()

    try:
        parser.feed(
            response.text[:MAX_HTML_LENGTH]
        )

    except Exception:
        return []

    findings = []

    for generator_value in parser.generator_values:
        findings.append(
            create_disclosure_finding(
                source="HTML meta tag",
                field_name="generator",
                value=generator_value,
                tested_url=tested_url
            )
        )

    return findings


def remove_duplicate_findings(
    findings: list[Finding]
) -> list[Finding]:
    """
    Removes findings containing identical evidence.
    """

    unique_findings = []
    seen_evidence = set()

    for finding in findings:
        if finding.evidence in seen_evidence:
            continue

        seen_evidence.add(
            finding.evidence
        )

        unique_findings.append(
            finding
        )

    return unique_findings


def check_technology_disclosure(
    url: str
) -> list[Finding]:
    """
    Passively checks whether the target explicitly discloses
    technology or software-version information.
    """

    findings = []

    try:
        response = httpx.get(
            url,
            headers=HEADERS,
            follow_redirects=True,
            timeout=10.0
        )

        tested_url = str(
            response.url
        )

        findings.extend(
            extract_header_disclosures(
                response=response,
                tested_url=tested_url
            )
        )

        findings.extend(
            extract_generator_disclosures(
                response=response,
                tested_url=tested_url
            )
        )

    except httpx.HTTPError as exc:
        findings.append(
            create_finding(
                rule_id="TECH-003",
                evidence=(
                    "The technology disclosure check could not "
                    f"be completed. Tested URL: {url}. "
                    f"Error: {exc}"
                )
            )
        )

    return remove_duplicate_findings(
        findings
    )