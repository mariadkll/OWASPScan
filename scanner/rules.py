from scanner.models import Finding


# Predefined rules for each possible scanner finding.
# Rules contain:
# name, category, risk, confidence, OWASP mapping, and description.
RULES = {
    "HDR-001": {
    "name": "Missing Strict-Transport-Security",
    "category": "HTTP Security Headers",
    "risk": "Medium",
    "confidence": "Likely",
    "owasp": "API8:2023 - Security Misconfiguration",
    "description": (
        "The HTTPS response did not include the "
        "Strict-Transport-Security header."
    )
    },

    "HDR-002": {
        "name": "Missing X-Content-Type-Options",
        "category": "HTTP Security Headers",
        "risk": "Low",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The response did not include the "
            "X-Content-Type-Options header."
        )
    },

    "HDR-003": {
        "name": "Weak X-Content-Type-Options value",
        "category": "HTTP Security Headers",
        "risk": "Low",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "X-Content-Type-Options was present but was not set to nosniff."
        )
    },

    "HDR-004": {
        "name": "Missing Content-Type",
        "category": "HTTP Security Headers",
        "risk": "Low",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The response did not declare its content type."
        )
    },

    "HDR-005": {
        "name": "Potentially sensitive response may be cacheable",
        "category": "HTTP Security Headers",
        "risk": "Medium",
        "confidence": "Possible",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "A potentially sensitive response did not include restrictive "
            "Cache-Control directives."
        )
    },

    "HDR-006": {
        "name": "Security header check inconclusive",
        "category": "HTTP Security Headers",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The scanner could not complete the security-header check."
        )
    },

    "CORS-001": {
    "name": "Arbitrary origin reflected with credentials",
    "category": "CORS Configuration",
    "risk": "High",
    "confidence": "Likely",
    "owasp": "API8:2023 - Security Misconfiguration",
    "description": (
        "The server reflected an untrusted Origin and allowed credentials. "
        "This may allow another website to access authenticated API responses."
        )
    },

    "CORS-002": {
        "name": "Arbitrary origin reflected",
        "category": "CORS Configuration",
        "risk": "Medium",
        "confidence": "Possible",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The server reflected an untrusted Origin. The impact depends on "
            "whether sensitive unauthenticated information is exposed."
        )
    },

    "CORS-003": {
        "name": "Wildcard CORS policy observed",
        "category": "CORS Configuration",
        "risk": "Info",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The server returned Access-Control-Allow-Origin: *. "
            "This may be intentional for a public API and is not automatically unsafe."
        )
    },

    "CORS-004": {
        "name": "Dynamic CORS response missing Vary Origin",
        "category": "CORS Configuration",
        "risk": "Low",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The server dynamically allowed an Origin without returning "
            "Vary: Origin, which may cause incorrect caching behavior."
        )
    },

    "CORS-005": {
        "name": "CORS test inconclusive",
        "category": "CORS Configuration",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The scanner could not obtain enough evidence to determine "
            "the target's CORS behavior."
        )
    },

    "PATH-001": {
        "name": "Possible sensitive path accessible",
        "category": "Sensitive File Exposure",
        "risk": "Medium",
        "confidence": "Possible",
        "owasp": "A02:2025 - Security Misconfiguration",
        "description": (
            "The response differed from the error-page baseline and contained "
            "patterns associated with the requested sensitive file. Manual "
            "verification is required to confirm exposure."
        )
    },

    "PATH-002": {
        "name": "Sensitive path exists but is protected",
        "category": "Sensitive File Exposure",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "N/A - Informational Observation",
        "description": (
            "Checks whether a sensitive-looking path returns 401 or 403."
        )
    },

    "OBJ-001": {
        "name": "Possible object-like path accessible",
        "category": "Object Path Discovery",
        "risk": "Medium",
        "confidence": "Possible",
        "owasp": "API1:2023 - Broken Object Level Authorization",
        "description": (
            "Checks whether an object-like path returns a response different "
            "from the baseline error page. This does not confirm IDOR."
        )
    },

    "OBJ-002": {
        "name": "Object-like path exists but is protected",
        "category": "Object Path Discovery",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "N/A - Informational Observation",
        "description": (
            "Checks whether an object-like path returns 401 or 403. "
            "This does not confirm IDOR."
        )
    },

    "TLS-001": {
        "name": "TLS connection failed",
        "category": "TLS Security",
        "risk": "High",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "Checks whether a TLS connection can be established on port 443."
        )
    },

    "TLS-002": {
        "name": "TLS certificate verification failed",
        "category": "TLS Security",
        "risk": "High",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "Checks whether the TLS certificate is trusted, valid, "
            "and matches the domain."
        )
    },

    "TLS-003": {
        "name": "TLS certificate expires soon",
        "category": "TLS Security",
        "risk": "Medium",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "Checks whether the TLS certificate is close to expiration."
        )
    },

    "TLS-004": {
        "name": "Could not read TLS certificate expiration date",
        "category": "TLS Security",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "Checks whether the certificate expiration date can be "
            "extracted and parsed."
        )
    },
    "TLS-005": {
        "name": "Expired TLS Certificate",
        "category": "TLS Security",
        "risk": "High",
        "confidence": "Confirmed",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The TLS certificate presented by the target has expired."
        )
    },

    "RATE-001": {
        "name": "No visible rate-limit metadata",
        "category": "Rate Limiting",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "description": (
            "No rate-limit headers were visible. This does not prove "
            "that rate limiting is absent."
        )
    },

    "RATE-002": {
        "name": "No visible throttling during limited test",
        "category": "Rate Limiting",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "description": (
            "The tested requests were accepted without HTTP 429. "
            "The limited test cannot confirm unrestricted resource consumption."
        )
    },

    "RATE-003": {
        "name": "Rate-limit control observed",
        "category": "Rate Limiting",
        "risk": "Info",
        "confidence": "Confirmed",
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "description": "The server returned HTTP 429 Too Many Requests."
    },

    "RATE-004": {
        "name": "Repeated access-denied responses observed",
        "category": "Request Protection",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "description": (
            "Repeated HTTP 401 or 403 responses may indicate authentication, "
            "WAF protection, or scanner blocking."
        )
    },

    "RATE-005": {
    "name": "Possible scanner blocking behavior",
    "category": "Rate Limiting",
    "risk": "Info",
    "confidence": "Uncertain",
    "owasp": "API8:2023 - Security Misconfiguration",
    "description": "Detects when the scanner cannot complete the rate-limit behavior test."
    },
    
    "TECH-001": {
    "name": "Software Version Disclosed",
    "category": "Technology Disclosure",
    "risk": "Low",
    "confidence": "Likely",
    "owasp": "API8:2023 - Security Misconfiguration",
    "description": (
        "The target explicitly disclosed a software product and version."
        )
    },

    "TECH-002": {
        "name": "Technology Information Disclosed",
        "category": "Technology Disclosure",
        "risk": "Info",
        "confidence": "Likely",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The target explicitly disclosed information about a technology "
            "used by the service."
        )
    },

    "TECH-003": {
        "name": "Technology Disclosure Check Inconclusive",
        "category": "Technology Disclosure",
        "risk": "Info",
        "confidence": "Uncertain",
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The technology disclosure check could not be completed."
        )
    }
}


def create_finding(
    rule_id: str,
    evidence: str,
) -> Finding:
    rule = RULES[rule_id]

    name = rule["name"]

    # if evidence:
    #     name = f"{name}: {evidence}"

    return Finding(
        category=rule["category"],
        name=name,
        risk=rule["risk"],
        evidence=evidence,
        rule_id=rule_id,
        confidence=rule["confidence"],
        owasp=rule["owasp"]
    )