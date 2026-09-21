import sys
from typing import Optional
from scanner.cors_checker import check_cors
from scanner.domain_validator import build_target
from scanner.headers_checker import check_headers
from scanner.models import Finding
from scanner.path_scanner import (
    scan_objects_paths,
    scan_path_exposure
)
from scanner.rate_limit_checker import check_rate_limiting
from scanner.technology_disclosure_checker import (
    check_technology_disclosure
)
from scanner.tls_checker import check_tls_certificate

from engine.risk_scoring import (
    generate_risk_summary,
    sort_findings
)

from reports.ai_report import (
    build_data,
    generate_ai_report
)

from reports.html_report import generate_html_report

from reports.terminal_report import (
    LoadingSpinner,
    print_banner,
    print_scan_complete,
    print_scan_stage,
    print_scan_warning,
    print_terminal_report
)


def run_check(
    name: str,
    check_function,
    target: str,
    findings: list[Finding]
) -> None:
    """
    Runs one scanner module and adds its findings
    to the main findings list.
    """

    print_scan_stage(
        f"Running {name}..."
    )

    try:
        check_findings = check_function(
            target
        )

        if check_findings:
            findings.extend(
                check_findings
            )

        print_scan_complete(
            f"{name} completed - "
            f"{len(check_findings or [])} finding(s)."
        )

    except Exception as error:
        print_scan_warning(
            f"{name} failed: {error}"
        )


def generate_ai_assessment(
    scan_data: dict
) -> Optional[dict]:
    """
    Generates the AI security assessment and shows
    the real error when generation fails.
    """

    spinner = LoadingSpinner(
        "Generating AI security assessment"
    )

    spinner.start()

    try:
        return generate_ai_report(
            scan_data
        )

    except Exception as error:
        print()

        print_scan_warning(
            "AI assessment generation failed: "
            f"{type(error).__name__}: {error}"
        )

        return None

    finally:
        spinner.stop()


def generate_manager_html_report(
    target_url: str,
    findings: list[Finding],
    risk_summary: dict,
    ai_report
):
    """
    Generates and serves the HTML report directly from memory.
    """

    import traceback

    spinner = LoadingSpinner(
        "Generating manager-friendly HTML report"
    )

    spinner.start()

    try:
        result = generate_html_report(
            target=target_url,
            findings=findings,
            risk_summary=risk_summary,
            ai_report=ai_report or {}
        )

    except Exception:
        spinner.stop()

        print()
        print_scan_warning(
            "HTML report generation failed."
        )

        traceback.print_exc()

        return None, None

    spinner.stop()

    return result


def main() -> None:
    """
    Runs the complete OWASPScan workflow.
    """

    print_banner()

    if len(sys.argv) < 2:
        print(
            "Usage: python3 main.py <domain-or-url>"
        )

        print(
            "Example: python3 main.py github.com"
        )

        return

    user_input = sys.argv[1].strip()

    try:
        target_domain, target_url = build_target(
            user_input
        )

    except ValueError as error:
        print(
            f"[ERROR] {error}"
        )

        return

    print()
    print(f"Target Domain : {target_domain}")
    print(f"Target URL    : {target_url}")
    print()

    findings: list[Finding] = []

    run_check(
        name="HTTP Headers",
        check_function=check_headers,
        target=target_url,
        findings=findings
    )

    run_check(
        name="Technology Disclosure",
        check_function=check_technology_disclosure,
        target=target_url,
        findings=findings
    )

    run_check(
        name="TLS Certificate",
        check_function=check_tls_certificate,
        target=target_domain,
        findings=findings
    )

    run_check(
        name="CORS",
        check_function=check_cors,
        target=target_url,
        findings=findings
    )

    run_check(
        name="Rate Limiting",
        check_function=check_rate_limiting,
        target=target_url,
        findings=findings
    )

    run_check(
        name="Sensitive Path Exposure",
        check_function=scan_path_exposure,
        target=target_url,
        findings=findings
    )

    run_check(
        name="Object Path Discovery",
        check_function=scan_objects_paths,
        target=target_url,
        findings=findings
    )

    # Sort findings from highest to lowest risk score.
    findings = sort_findings(
        findings
    )

    # Calculate the official deterministic risk summary.
    risk_summary = generate_risk_summary(
        findings
    )

    # Build the finalized data supplied to Gemma.
    scan_data = build_data(
        target=target_url,
        findings=findings,
        risk_summary=risk_summary
    )

    print()

    # Generate the AI assessment first.
    ai_report = generate_ai_assessment(
        scan_data
    )

    if ai_report:
        print_scan_complete(
            "AI security assessment generated."
        )

    else:
        print_scan_warning(
            "AI assessment could not be generated. "
            "The technical report will still be displayed."
        )

    # Generate and start serving the HTML report before
    # printing the complete terminal report.
    (
        html_server,
        html_report_link
    ) = generate_manager_html_report(
        target_url=target_url,
        findings=findings,
        risk_summary=risk_summary,
        ai_report=ai_report
    )

    if html_report_link:
        print_scan_complete(
            "Manager-friendly HTML report generated."
        )

    else:
        print_scan_warning(
            "The HTML report could not be generated. "
            "The terminal report remains valid."
        )

    # Print all results together after the AI and HTML
    # generation steps have completed.
    print_terminal_report(
        target=target_url,
        findings=findings,
        risk_summary=risk_summary,
        ai_report=ai_report,
        html_report_link=html_report_link
    )

    # Keep the in-memory HTML report available until
    # the user closes the program.
    if html_server:
        print()
        print(
            "The HTML report is available while "
            "OWASPScan remains running."
        )

        print(
            f"Open report: {html_report_link}"
        )

        try:
            input(
                "Press Enter to close the report and exit..."
            )

        except KeyboardInterrupt:
            print()

        finally:
            html_server.shutdown()
            html_server.server_close()


if __name__ == "__main__":
    main()