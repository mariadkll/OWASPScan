import re


DOMAIN_PATTERN = re.compile(r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

def validate_domain(domain: str) -> str: 
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        raise ValueError("Enter only domain name, e.g: example.com")
    if "/" in domain:
        raise ValueError("Enter only domain name, e.g: example.com")
    if not DOMAIN_PATTERN.match(domain):
        raise ValueError("Invalid domain format, e.g: example.com")

    return domain

def build_target(domain: str) -> tuple[str, str] :

    domain = validate_domain(domain)
    url = f"https://{domain}"
    target = [domain, url]
    return target


