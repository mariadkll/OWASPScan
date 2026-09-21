import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from scanner.models import Finding
from scanner.rules import create_finding


TIMEOUT = 5
TLS_PORT = 443
EXPIRY_WARNING_DAYS = 30


def get_tls_certificate(domain: str) -> Optional[dict]:
    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, TLS_PORT),
        timeout = TIMEOUT
    ) as sock:
        with context.wrap_socket(sock, server_hostname= domain) as tls_socket:
            certificate = tls_socket.getpeercert()
            return certificate
        

def parse_certificate_expiry(certificate: dict) -> Optional[datetime]:
    not_after = certificate.get("notAfter")

    if not not_after:
        return None
    
    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

    return expiry_date.replace(tzinfo = timezone.utc)

def get_certificate_subject(certificate: dict) -> str:
    subject = certificate.get("subject", [])

    parts = []
    for item in subject:
        for key, value in item:
            parts.append(f"{key} = {value}")

    return ",".join(parts)


def get_certificate_issuer(certificate: dict) -> str:
    issuer = certificate.get("issuer", [])

    parts = []

    for item in issuer:
        for key, value in item:
            parts.append(f"{key} = {value}")
    
    return ",".join(parts)


def check_tls_certificate(domain: str) ->list[Finding]:
    findings = []

    if not domain:
        findings.append(
            create_finding(
                rule_id="TLS-001",
                evidence=(
                    "The target domain could not be parsed. "
                    f"target: {domain}"
                    "detection_method: TLS domain normalization"
                )
            )
        )
        return findings
    
    try:
        certificate = get_tls_certificate(domain)
        if not certificate:
            findings.append(
                create_finding(
                    rule_id="TLS-001",
                    evidence=(
                        "No TLS certificate was returned by the server."
                        f"domain: {domain}"
                        f"port: {TLS_PORT}"
                        "detection_method: TLS certificate retrieval"
                    )

                )
            )
            return findings
    
        expiry_date = parse_certificate_expiry(certificate)
        if not expiry_date:
            findings.append(
            create_finding(
                rule_id="TLS-004",
                evidence=(
                    "The certificate expiration date could not be read."
                    f"domain: {domain}"
                    f"certificate_subject: {get_certificate_subject(certificate)}"
                    f"certificate_issuer {get_certificate_issuer(certificate)}"
                    "detection_method: certificate expiration parsing"
                )
            )
        )
            return findings
        
        date_now = datetime.now(timezone.utc)
        days_until_expiry = (expiry_date - date_now).days

        if days_until_expiry < 0:
            findings.append(
            create_finding(
                rule_id="TLS-005",
                evidence=(
                    f"Target domain: {domain}. "
                    f"The TLS certificate expired "
                    f"{abs(days_until_expiry)} days ago."
                )
            )
        )
        elif days_until_expiry <= EXPIRY_WARNING_DAYS:
            findings.append(
                create_finding(
                    rule_id="TLS-003",
                    evidence=(
                        f"TLS certificate expires in {days_until_expiry} days "
                        f"on {expiry_date.strftime('%Y-%m-%d')}. "
                        f"domain: {domain}"
                    )
                )
            )
            return findings
        



    except ssl.SSLCertVerificationError as error:
        findings.append(
        create_finding(
            rule_id="TLS-002",
            evidence=(
                f"TLS certificate verification failed: {error}"
                f"domain : {domain}"
                f"port: {TLS_PORT}"
                f"error: {str(error)}" 
                "detection_method: verified TLS handshake"
            )
            
        )
    )
        return findings
    
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as error:
        findings.append(
            create_finding(
                rule_id="TLS-001",
                evidence= (
                    f"Could not establish TLS connection: {error}"
                    f"domain : {domain}"
                    f"port: {TLS_PORT}"
                    f"error: {str(error)}" 
                    "detection_method: TLS socket connection"
              )
            )
        )

        return findings
    
    return findings





    