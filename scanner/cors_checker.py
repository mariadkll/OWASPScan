import httpx
from scanner.models import Finding
from scanner.rules import create_finding


TIMEOUT = 5
TEST_ORIGIN = "https://owaspscan.invalid"

def check_cors(domain: str) -> list[Finding]:

    findings = []

    try:
        with httpx.Client(timeout= TIMEOUT, follow_redirects= True) as client:
            response = client.get(
                            domain,
                            headers={
                                "Origin": TEST_ORIGIN,
                                "User-Agent": "OWASPScan/1.0",
                                "Accept": "text/html,application/json,*/*"
                            }
                        )

            allowed_origin = response.headers.get( 
                "access-control-allow-origin",
                ""
            )

            allowed_credentials = response.headers.get(
                "access-control-allow-credentials",
                ""
            ).lower()

            vary_header = response.headers.get(
                "vary",
                ""
            ).lower()

            if not allowed_origin:
                return findings
            
            if allowed_origin == TEST_ORIGIN and allowed_credentials == "true":
                findings.append(
                    create_finding(
                        rule_id="CORS-001",
                        evidence=(
                        f"Tested URL: {domain}. "
                        f"Sent Origin: {TEST_ORIGIN}. "
                        f"The server returned "
                        f"Access-Control-Allow-Origin: {allowed_origin} "
                        "and Access-Control-Allow-Credentials: true. "
                        "Manual verification is recommended."
                        )
                    )
                )

            elif allowed_origin == TEST_ORIGIN:
                findings.append(
                    create_finding(
                        rule_id="CORS-002",
                        evidence=(
                        f"Tested URL: {domain}. "
                        f"Sent Origin: {TEST_ORIGIN}. "
                        f"The server reflected the origin using "
                        f"Access-Control-Allow-Origin: {allowed_origin}. "
                        "The impact depends on the sensitivity of the response."
                        )
                    )
                )
            
            elif allowed_origin == "*":
                findings.append(
                    create_finding(
                        rule_id="CORS-003",
                        evidence=(
                        f"Tested URL: {domain}. "
                        "The server returned "
                        "Access-Control-Allow-Origin: *. "
                        "This may be intentional for a public API and does "
                        "not automatically represent a vulnerability."
                        )
                    )
                )
            if allowed_origin == TEST_ORIGIN and "origin" not in vary_header:
                findings.append(
                    create_finding(
                        rule_id="CORS-004",
                        evidence=(
                        f"Tested URL: {domain}. "
                        "The server dynamically reflected the supplied Origin "
                        "but did not return Vary: Origin. "
                        f"Returned Vary header: {vary_header or 'not present'}."
                        )
                    )
                )

    except httpx.HTTPError as error:
        findings.append(
            create_finding(
                rule_id="CORS-005",
                evidence=(
                    f"Tested URL: {domain}. "
                    f"The CORS check could not be completed: {error}."
                )
            )
        )

    return findings
