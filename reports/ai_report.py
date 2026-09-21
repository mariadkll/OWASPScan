from typing import Any, Dict, List

from scanner.models import Finding
import json 

import httpx


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:4b"
OLLAMA_TIMEOUT = 300

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {
            "type": "string"
        },
        "overall_assessment": {
            "type": "string"
        },
        "key_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string"
                    },
                    "owasp": {
                        "type": "string"
                    },
                    "finding": {
                        "type": "string"
                    },
                    "details": {
                        "type": "string"
                    },
                    "verification": {
                        "type": "string"
                    }
                },
                "required": [
                    "rule_id",
                    "owasp",
                    "finding",
                    "details",
                    "verification"
                ],
                "additionalProperties": False
            }
        },
        "recommended_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {
                        "type": "integer"
                    },
                    "action": {
                        "type": "string"
                    },
                    "reason": {
                        "type": "string"
                    },
                    "related_rule_ids": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": [
                    "priority",
                    "action",
                    "reason",
                    "related_rule_ids"
                ]
            }
        },
        "limitations": {
            "type": "string"
        },
        "conclusion": {
            "type": "string"
        }
    },
    "required": [
        "executive_summary",
        "overall_assessment",
        "key_findings",
        "recommended_actions",
        "limitations",
        "conclusion"
    ]
}


def finding_to_dict(finding: Finding) -> Dict[str, Any]:

    return {
        "rule_id": finding.rule_id,
        "name": finding.name,
        "category": finding.category,
        "risk": finding.risk,
        "confidence": finding.confidence,
        "owasp": finding.owasp,
        "evidence": finding.evidence
    }


def findings_to_dict(findings: list[Finding]) -> Dict[str, Any]:

    findings_dict = []


    for finding in findings:
        findings_dict.append(finding_to_dict(finding))
        

    return findings_dict


def build_data(
        target: str,
        risk_summary: Dict[str, Any],
        findings: List[Finding]    
) -> Dict[str, Any]:
    

    scan_data = {
        "target" : target,
        "total_findings" : len(findings),
        "overall_rating": risk_summary["overall_rating"],
        "total_score": risk_summary["total_score"],
        "average_score": risk_summary["average_score"],
        "findings": findings_to_dict(findings)
    }

    return scan_data




def build_system_prompt() -> str:
    """
    Defines Gemma's reporting role and accuracy requirements.
    """

    system_prompt = """
You are the reporting component of OWASPScan.

OWASPScan is an external web and API security misconfiguration scanner.

Generate a clear, concise and professional security assessment for the
tested domain. The report may be read by users with limited cybersecurity
knowledge.

Accuracy requirements:

1. Use only the supplied OWASPScan results.
2. Do not invent vulnerabilities, endpoints, evidence or attack results.
3. Do not change rule IDs, OWASP mappings, risk levels, confidence levels,
   scores or the overall rating.
4. Describe only what the scanner observed.
5. Use conditional language when a finding is not confirmed.
6. Possible and Uncertain findings require manual verification.
7. Object-path discovery does not confirm BOLA or unauthorized access.
8. Missing rate-limit metadata does not confirm that rate limiting is absent.
9. A limited test without HTTP 429 does not confirm unrestricted requests.
10. Missing HSTS does not confirm that traffic or credentials were intercepted.
11. Missing X-Content-Type-Options does not confirm that content was executed.
12. Do not exaggerate security impact.
13. Keep each explanation direct and concise.

For every supplied finding, create one key_findings entry in the same order.

Each key finding must contain:

- rule_id: copied exactly for internal matching;
- owasp: copied exactly from the supplied finding;
- finding: a direct description of what was observed;
- details: a concise explanation of its security relevance;
- verification: the appropriate manual review or verification step.

Return only valid JSON matching the supplied schema.
Do not return HTML, Markdown or code fences.
"""

    return system_prompt.strip()

   
def build_report_prompt(scan_data: dict) -> str:
    """
    Builds the user prompt sent to Gemma using the finalized
    OWASPScan findings and deterministic risk results.
    """

    scan_json = json.dumps(
        scan_data,
        indent=2
    )

    report_prompt = f"""
Generate a clear, concise, professional and OWASP-aligned security assessment
for the tested domain.

The raw technical findings are displayed separately in the terminal report.
Do not repeat complete technical evidence, confidence values, risk scores or
internal implementation details unnecessarily.

GENERAL REQUIREMENTS

1. Use only the supplied OWASPScan data.
2. Do not invent vulnerabilities, endpoints, technologies, evidence or attacks.
3. Do not change rule IDs, OWASP mappings, risk levels, confidence levels,
   scores or the overall rating.
4. Create exactly one key_findings entry for every supplied finding.
5. Preserve the original finding order.
6. Copy each rule_id exactly.
7. Copy each OWASP mapping exactly.
8. Describe only what OWASPScan observed.
9. Keep the wording clear and straight to the point.
10. Do not use alarmist or exaggerated language.
11. Do not describe Possible or Uncertain observations as confirmed issues.
12. Do not claim that a successful attack, breach or exploitation occurred.
13. Do not connect technologies or versions to CVEs, NVD records, known
    vulnerabilities or exploitability unless OWASPScan supplied that evidence.
14. Do not return Markdown, HTML, commentary or code fences.
15. Return only valid JSON matching the supplied schema.

KEY FINDING FORMAT

For every supplied finding, produce:

- rule_id:
  Copy the supplied rule ID exactly. This is used internally and is not
  displayed to the user.

- owasp:
  Copy the supplied OWASP mapping exactly.

- finding:
  State directly what was observed on the tested domain.

- details:
  Briefly explain the security relevance of the observation without
  exaggerating its impact.

- verification:
  Provide a practical manual review or verification step.

SPECIFIC INTERPRETATION REQUIREMENTS

HDR-001:
Finding: State that Strict-Transport-Security was not present in the tested
HTTPS response.
Details: Explain that HSTS helps supported browsers consistently use HTTPS.
Do not claim that traffic, credentials or information were intercepted.
Verification: Recommend confirming whether HSTS is enabled across the domain
and reviewing its max-age and subdomain policy.

HDR-002:
Finding: State that X-Content-Type-Options was not configured with the
recommended nosniff value.
Details: Explain that nosniff prevents supported browsers from interpreting
content as a different media type from the one declared by the server.
Do not claim that content or code was executed.
Verification: Recommend confirming that the header is set to nosniff and that
responses use accurate Content-Type values.

RATE-001:
Finding: State that no visible rate-limit information or retry metadata was
returned by the tested service.
Details: Clearly state that this does not confirm that rate limiting is absent.
Request limits may be enforced by the application, gateway, reverse proxy or
hosting infrastructure.
Verification: Recommend reviewing the application and infrastructure
configuration to confirm whether request limits are enforced.

RATE-002:
Finding: State that no visible throttling response was observed during the
limited request test.
Details: Clearly state that this does not confirm unrestricted request
handling. Throttling may depend on the endpoint, authentication state, client
identity, request volume or evaluation period.
Verification: Recommend an authorized controlled test using documented limits
and representative endpoints.

PATH-001:
Finding: State that a tested path returned a response that differed from the
target's normal error-page baseline.
Details: Explain that this may indicate accessible content, but it does not
confirm that a sensitive file or resource was exposed.
Verification: Recommend manually reviewing the returned path, response body,
headers and access requirements.

PATH-002:
Finding: State that a tested path returned an authentication or authorization
response such as HTTP 401 or 403.
Details: Explain that the path may exist but appears protected based on the
external response.
Verification: Recommend confirming that access controls are intentional and
consistently enforced.

OBJ-001:
Finding: State that an object-like path returned an accessible response.
Details: Clearly state that this does not confirm BOLA, IDOR or unauthorized
access because authenticated authorization testing was not performed.
Verification: Recommend testing only in an authorized environment using
multiple controlled user accounts and known object ownership boundaries.

OBJ-002:
Finding: State that an object-like path returned a protected response.
Details: Explain that the external response suggests access control is present,
but does not fully verify authorization behavior.
Verification: Recommend confirming object-level authorization using authorized
authenticated test accounts.

TECH-001:
Finding: State which software or technology and exact version were explicitly
disclosed by the tested domain.
Details: Explain that exact version information can assist technology
fingerprinting and help narrow further security research.
Do not claim that the disclosed version is vulnerable, exploitable or connected
to a CVE.
Verification: Recommend reviewing whether the exact version needs to be exposed
and removing unnecessary version information where appropriate.

TECH-002:
Finding: State which technology name was explicitly disclosed.
Details: Explain that the disclosure provides information about the target's
technology stack but does not by itself confirm a vulnerability.
Verification: Recommend reviewing whether the identifying response header or
HTML metadata is necessary.

TECH-003:
Finding: State that the technology-disclosure check could not be completed.
Details: Explain that this is an inconclusive scan result and not a confirmed
security weakness.
Verification: Recommend manually reviewing the target's response headers and
HTML metadata.

EXECUTIVE SUMMARY

Write a concise overview of the tested domain's externally observed security
configuration.

Mention:

- the overall risk rating;
- the number and general severity of findings;
- the most important OWASP-related configuration areas;
- that external observations do not confirm exploitation.

OVERALL ASSESSMENT

Explain what the deterministic risk result means for the tested domain.

Do not recalculate or modify the supplied overall rating or scores.

RECOMMENDED ACTIONS

Provide practical actions ordered by priority.

Each action must:

- address one or more supplied findings;
- include only supplied rule IDs;
- avoid duplicate recommendations;
- use clear and professional language;
- distinguish required remediation from manual verification.

SCAN LIMITATIONS

Explain that OWASPScan performs limited external observation.

Mention relevant limitations such as:

- no authenticated access;
- no source-code review;
- no destructive testing;
- no confirmed exploitability testing;
- possible influence from CDNs, WAFs, proxies, redirects and custom error pages;
- limited rate-limit testing;
- object-path observations do not confirm BOLA or IDOR;
- technology disclosure does not confirm software vulnerability.

CONCLUSION

Provide a concise final statement describing the domain's observed security
configuration and the importance of reviewing the supplied findings.

Return only valid JSON matching the structured output schema supplied
with this request.

FINALIZED OWASPSCAN DATA:

{scan_json}
"""

    return report_prompt.strip()



def generate_ai_report(
    scan_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generates the structured AI security assessment.
    """

    system_instructions = build_system_prompt()

    report_prompt = build_report_prompt(
        scan_data
    )

    request_data = {
        "model": OLLAMA_MODEL,
        "system": system_instructions,
        "prompt": report_prompt,
        "format": REPORT_SCHEMA,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_ctx": 16384,
            "num_predict": 4096
        }
    }

    try:
        response = httpx.post(
            OLLAMA_URL,
            json=request_data,
            timeout=httpx.Timeout(
                300.0,
                connect=10.0
            )
        )

        response.raise_for_status()

        response_data = response.json()

        done_reason = response_data.get(
            "done_reason",
            ""
        )

        if done_reason == "length":
            raise ValueError(
                "Gemma reached its output limit before "
                "completing the assessment."
            )

        generated_content = response_data.get(
            "response",
            ""
        ).strip()

        if not generated_content:
            raise ValueError(
                "Gemma returned an empty report."
            )

        generated_report = json.loads(
            generated_content
        )

        return complete_ai_findings(
            ai_report=generated_report,
            scan_data=scan_data
        )

    except httpx.HTTPError as error:
        print(
            "[AI REPORT ERROR] Could not communicate "
            f"with Ollama: {error}"
        )

    except json.JSONDecodeError as error:
        print(
            "[AI REPORT ERROR] Gemma returned incomplete "
            f"or invalid JSON: {error}"
        )

    except Exception as error:
        print(
            "[AI REPORT ERROR] "
            f"{type(error).__name__}: {error}"
        )

    return {}


def complete_ai_findings(
    ai_report: dict,
    scan_data: dict
) -> dict:
    """
    Ensures that every original OWASPScan finding has a matching
    AI explanation with all required user-facing fields.
    """

    generated_by_rule = {
        item.get("rule_id"): item
        for item in ai_report.get("key_findings", [])
        if item.get("rule_id")
    }

    completed_findings = []

    for original in scan_data.get("findings", []):
        rule_id = original.get("rule_id", "")
        generated = generated_by_rule.get(
            rule_id,
            {}
        )

        owasp = generated.get(
            "owasp",
            ""
        ).strip()

        if not owasp:
            owasp = original.get(
                "owasp",
                "OWASP mapping unavailable"
            )

        finding_text = generated.get(
            "finding",
            ""
        ).strip()

        if not finding_text:
            finding_text = original.get(
                "name",
                "A security-related observation was identified."
            )

        details = generated.get(
            "details",
            ""
        ).strip()

        if not details:
            details = (
                "This observation identifies a configuration area that "
                "should be reviewed. The available evidence does not "
                "confirm a successful attack or security breach."
            )

        verification = generated.get(
            "verification",
            ""
        ).strip()

        if not verification:
            confidence = original.get(
                "confidence",
                "Unknown"
            )

            if confidence in [
                "Possible",
                "Uncertain"
            ]:
                verification = (
                    "Review the configuration and evidence manually before "
                    "treating this observation as a confirmed issue."
                )
            else:
                verification = (
                    "Review the affected configuration and confirm whether "
                    "remediation is appropriate."
                )

        completed_findings.append(
            {
                "rule_id": rule_id,
                "owasp": owasp,
                "finding": finding_text,
                "details": details,
                "verification": verification
            }
        )

    ai_report["key_findings"] = completed_findings

    return ai_report