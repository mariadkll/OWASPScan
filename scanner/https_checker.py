import httpx
from scanner.models import Finding

TIMEOUT = 5


def check_https(domain: str) -> list[Finding]:
    findings = []

    https_domain = f"https://{domain}"
    http_domain = f"http://{domain}"

    try:
        response = httpx.get(https_domain, timeout = TIMEOUT, follow_redirects = True)
        if response.status_code >= 500:
            findings.append(
                Finding(
                    category="HTTPS",
                    name="HTTPS Server Error",
                    risk= "Medium",
                    evidence=f"HTTPS status code: {response.status_code}"
                )
            )
    except Exception as error:
        findings.append(
            Finding(
                category= "HTTPS",
                name= "HTTPS not available",
                risk ="High",
                evidence= str(error)
            )
        )
    
    try:
        response = httpx.get(
            http_domain,
            timeout=TIMEOUT,
            follow_redirects=True
        )

        final_url = str(response.url)

        if not final_url.startswith("https://"):
            findings.append(
                Finding(
                    category="HTTPS",
                    name= "HTTP does not strictly enforce HTTPS",
                    risk= "Medium",
                    evidence= f"Final URL after redirects: {final_url}"
                )
            )

    except Exception as error:
        findings.append(
            Finding(
                category="HTTPS",
                name="HTTP redirect check failed",
                risk="Info",
                evidence=str(error)
            )
        )
    
    return findings