from datetime import datetime
import itertools
import sys
import textwrap
import threading
import time


from scanner.models import Finding



REPORT_WIDTH = 90

# Terminal formatting
RESET = "\033[0m"
BOLD = "\033[1m"

# Risk colors
RED = "\033[91m"
YELLOW = "\033[93m"
GRAY = "\033[90m"


def get_risk_color(risk: str) -> str:
    """
    Returns the terminal color associated with a finding's risk.

    Critical and High: Red
    Medium: Yellow
    Low and Info: Gray
    """

    risk_colors = {
        "Critical": RED,
        "High": RED,
        "Medium": YELLOW,
        "Low": GRAY,
        "Info": GRAY
    }

    return risk_colors.get(risk, GRAY)


def format_owasp_title(owasp: str) -> str:
    """
    Adds 'OWASP' before the mapping without printing it twice.
    """

    owasp = str(owasp).strip()

    if not owasp:
        return "OWASP mapping unavailable"

    if owasp.lower().startswith("owasp"):
        return owasp

    return f"OWASP {owasp}"


class LoadingSpinner:
    """
    Displays a terminal spinner while an operation is running.
    """

    def __init__(
        self,
        message: str = "Loading"
    ) -> None:
        self.message = message
        self.stop_event = threading.Event()
        self.thread = None

    def _animate(self) -> None:
        symbols = itertools.cycle(
            ["|", "/", "-", "\\"]
        )

        while not self.stop_event.is_set():
            symbol = next(symbols)

            sys.stdout.write(
                f"\r[*] {self.message} {symbol}"
            )

            sys.stdout.flush()
            time.sleep(0.1)

    def start(self) -> None:
        self.stop_event.clear()

        self.thread = threading.Thread(
            target=self._animate,
            daemon=True
        )

        self.thread.start()

    def stop(
        self,
        final_message: str = None
    ) -> None:
        self.stop_event.set()

        if self.thread:
            self.thread.join()

        # Clear the spinner line.
        sys.stdout.write(
            "\r" + " " * REPORT_WIDTH + "\r"
        )

        sys.stdout.flush()

        if final_message:
            print(f"[+] {final_message}")


def print_banner() -> None:
    """
    Prints the OWASPScan application banner.
    """

    print()
    print("=" * REPORT_WIDTH)
    print("OWASPScan".center(REPORT_WIDTH))

    print(
        "Web Security Misconfiguration Scanner".center(
            REPORT_WIDTH
        )
    )

    print("=" * REPORT_WIDTH)


def print_scan_stage(message: str) -> None:
    """
    Prints the beginning of a scan stage.
    """

    print(f"[*] {message}")


def print_scan_complete(message: str) -> None:
    """
    Prints a successful scan-stage message.
    """

    print(f"[+] {message}")


def print_scan_warning(message: str) -> None:
    """
    Prints a warning or failure message.
    """

    print(f"[!] {message}")


def count_risk(
    findings: list[Finding],
    risk: str
) -> int:
    """
    Counts findings matching a specific risk level.
    """

    return sum(
        1
        for finding in findings
        if finding.risk == risk
    )


def print_wrapped_text(
    text: str,
    report_width: int = REPORT_WIDTH
) -> None:
    """
    Prints paragraph text without exceeding the report width.
    """

    wrapped_lines = textwrap.wrap(
        str(text),
        width=report_width,
        break_long_words=False,
        break_on_hyphens=False
    )

    if not wrapped_lines:
        print("No information available.")
        return

    for line in wrapped_lines:
        print(line)


def print_wrapped_field(
    label: str,
    value: str,
    report_width: int = REPORT_WIDTH
) -> None:
    """
    Prints a labeled field and wraps long values underneath it.
    """

    label_width = 12
    label_text = f"{label:<{label_width}}: "

    available_width = (
        report_width - len(label_text)
    )

    wrapped_lines = textwrap.wrap(
        str(value),
        width=available_width,
        break_long_words=False,
        break_on_hyphens=False
    )

    if not wrapped_lines:
        print(f"{label_text}Not available")
        return

    print(
        f"{label_text}{wrapped_lines[0]}"
    )

    continuation_indent = " " * len(
        label_text
    )

    for line in wrapped_lines[1:]:
        print(
            f"{continuation_indent}{line}"
        )


def print_report_header(
    target: str,
    findings: list[Finding],
    risk_summary: dict
) -> None:
    """
    Prints general scan information and the risk summary.
    """

    print()
    print("=" * REPORT_WIDTH)

    print(
        "SECURITY ASSESSMENT REPORT".center(
            REPORT_WIDTH
        )
    )

    print("=" * REPORT_WIDTH)

    print(f"{'Target':<16}: {target}")

    print(
        f"{'Scan time':<16}: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"{'Total findings':<16}: "
        f"{len(findings)}"
    )

    print(
        f"{'Overall rating':<16}: "
        f"{risk_summary['overall_rating']}"
    )

    print(
        f"{'Total risk score':<16}: "
        f"{risk_summary['total_score']:.2f}"
    )

    print(
        f"{'Average score':<16}: "
        f"{risk_summary['average_score']:.2f}"
    )

    print("-" * REPORT_WIDTH)
    print("RISK SUMMARY")
    print("-" * REPORT_WIDTH)

    print(
        f"Critical: {count_risk(findings, 'Critical')} | "
        f"High: {count_risk(findings, 'High')} | "
        f"Medium: {count_risk(findings, 'Medium')} | "
        f"Low: {count_risk(findings, 'Low')} | "
        f"Info: {count_risk(findings, 'Info')}"
    )


def print_finding(
    finding: Finding,
    index: int
) -> None:
    """
    Prints one raw technical finding.

    Only the finding name and risk level are colored.
    """

    risk_color = get_risk_color(
        finding.risk
    )

    print()

    print(
        risk_color
        + BOLD
        + f"[{index:02d}] {finding.name}"
        + RESET
    )

    print(
        f"{'Rule ID':<12}: "
        f"{finding.rule_id}"
    )

    print(
        f"{'Category':<12}: "
        f"{finding.category}"
    )

    print(
        f"{'Risk':<12}: "
        + risk_color
        + BOLD
        + finding.risk
        + RESET
    )

    print(
        f"{'Confidence':<12}: "
        f"{finding.confidence}"
    )

    print(
        f"{'OWASP':<12}: "
        f"{finding.owasp}"
    )

    if finding.evidence:
        print_wrapped_field(
            label="Evidence",
            value=finding.evidence
        )

    print("-" * REPORT_WIDTH)


def print_ai_assessment(
    ai_report: dict,
    report_width: int = REPORT_WIDTH
) -> None:
    """
    Prints Gemma's user-friendly assessment after all raw
    technical findings have been displayed.
    """

    if not ai_report:
        return

    print()
    print("=" * report_width)

    print(
        "AI SECURITY ASSESSMENT".center(
            report_width
        )
    )

    print("=" * report_width)

    executive_summary = ai_report.get(
        "executive_summary",
        "No executive summary was generated."
    )

    print("EXECUTIVE SUMMARY")
    print("-" * report_width)

    print_wrapped_text(
        executive_summary,
        report_width
    )

    print()
    print("OVERALL ASSESSMENT")
    print("-" * report_width)

    overall_assessment = ai_report.get(
        "overall_assessment",
        "No overall assessment was generated."
    )

    print_wrapped_text(
        overall_assessment,
        report_width
    )

    key_findings = ai_report.get(
        "key_findings",
        []
    )

    if key_findings:
        print()
        print("OWASP-ALIGNED FINDINGS")
        print("-" * report_width)

        for finding in key_findings:
            owasp = finding.get(
                "owasp",
                "Mapping unavailable"
            )

            finding_text = finding.get(
                "finding",
                "No finding description was generated."
            )

            details = finding.get(
                "details",
                "No additional details were generated."
            )

            verification = finding.get(
                "verification",
                "Manual review is recommended."
            )

            print()
            print(format_owasp_title(owasp))

            print_wrapped_field(
                label="Finding",
                value=finding_text,
                report_width=report_width
            )

            print_wrapped_field(
                label="Details",
                value=details,
                report_width=report_width
            )

            print_wrapped_field(
                label="Verification",
                value=verification,
                report_width=report_width
            )

    recommended_actions = ai_report.get(
        "recommended_actions",
        []
    )

    if recommended_actions:
        print()
        print("RECOMMENDED ACTIONS")
        print("-" * report_width)

        for action in recommended_actions:
            priority = action.get(
                "priority",
                "-"
            )

            action_text = action.get(
                "action",
                "No action was generated."
            )

            reason = action.get(
                "reason",
                ""
            )

            related_rule_ids = action.get(
                "related_rule_ids",
                []
            )

            print()
            print(
                f"Priority {priority}: "
                f"{action_text}"
            )

            if related_rule_ids:
                print_wrapped_field(
                    label="Related rules",
                    value=", ".join(
                        related_rule_ids
                    ),
                    report_width=report_width
                )

            if reason:
                print_wrapped_field(
                    label="Reason",
                    value=reason,
                    report_width=report_width
                )

    print()
    print("SCAN LIMITATIONS")
    print("-" * report_width)

    limitations = ai_report.get(
        "limitations",
        "No limitations section was generated."
    )

    print_wrapped_text(
        limitations,
        report_width
    )

    print()
    print("CONCLUSION")
    print("-" * report_width)

    conclusion = ai_report.get(
        "conclusion",
        "No conclusion was generated."
    )

    print_wrapped_text(
        conclusion,
        report_width
    )


def print_terminal_report(
    target: str,
    findings: list[Finding],
    risk_summary: dict,
    ai_report: dict = None,
    html_report_link: str = None
) -> None:
    """
    Prints the complete terminal report.

    Order:
    1. General report information
    2. Risk summary
    3. Raw technical findings
    4. AI security assessment
    5. End of report
    """

    print_report_header(
        target=target,
        findings=findings,
        risk_summary=risk_summary
    )

    print("-" * REPORT_WIDTH)
    print("RAW TECHNICAL FINDINGS")
    print("-" * REPORT_WIDTH)

    if findings:
        for index, finding in enumerate(
            findings,
            start=1
        ):
            print_finding(
                finding=finding,
                index=index
            )

    else:
        print()
        print("No technical findings were detected.")
        print()

    # All raw technical findings have now finished printing.
    print("=" * REPORT_WIDTH)

    print(
        "END OF RAW FINDINGS".center(
            REPORT_WIDTH
        )
    )

    print("=" * REPORT_WIDTH)

    # The AI assessment starts only after the raw findings section.
    if ai_report:
        print_ai_assessment(
            ai_report=ai_report,
            report_width=REPORT_WIDTH
        )

    else:
        print()
        print("=" * REPORT_WIDTH)

        print(
            "AI SECURITY ASSESSMENT".center(
                REPORT_WIDTH
            )
        )

        print("=" * REPORT_WIDTH)

        print_wrapped_text(
            "The AI assessment was unavailable. "
            "The raw technical findings above remain valid."
        )

    print()
    print("-" * REPORT_WIDTH)
    print("REPORT FILES")
    print("-" * REPORT_WIDTH)

    if html_report_link:
        print_wrapped_field(
            label="HTML report",
            value=html_report_link,
            report_width=REPORT_WIDTH
        )

    else:
        print(
            "HTML report : Not available"
        )


    print()
    print("=" * REPORT_WIDTH)

    print(
        "END OF REPORT".center(
            REPORT_WIDTH
        )
    )

    print("=" * REPORT_WIDTH)