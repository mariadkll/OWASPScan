# from datetime import datetime
# from html import escape
# import threading
# from http.server import (
#     BaseHTTPRequestHandler,
#     ThreadingHTTPServer
# )
# from typing import Optional, Tuple

# from scanner.models import Finding


# def safe_text(value) -> str:
#     """
#     Converts report data into safely escaped HTML text.
#     """

#     if value is None:
#         return ""

#     return escape(
#         str(value),
#         quote=True
#     )


# def count_risk(
#     findings: list[Finding],
#     risk: str
# ) -> int:
#     """
#     Counts findings matching the supplied risk level.
#     """

#     return sum(
#         1
#         for finding in findings
#         if finding.risk == risk
#     )


# def get_risk_class(
#     risk: str
# ) -> str:
#     """
#     Returns the CSS class used for a risk level.
#     """

#     risk = str(risk).lower()

#     if risk in [
#         "critical",
#         "high"
#     ]:
#         return "risk-high"

#     if risk == "medium":
#         return "risk-medium"

#     return "risk-low"


# def render_recommended_actions(
#     ai_report: dict
# ) -> str:
#     """
#     Converts the AI recommended actions into HTML.
#     """

#     actions = ai_report.get(
#         "recommended_actions",
#         []
#     )

#     if not actions:
#         return """
#         <p class="empty-message">
#             No recommended actions were generated.
#         </p>
#         """

#     html_parts = []

#     for action in actions:
#         if isinstance(action, str):
#             html_parts.append(
#                 f"""
#                 <div class="action-card">
#                     <p>{safe_text(action)}</p>
#                 </div>
#                 """
#             )

#             continue

#         priority = action.get(
#             "priority",
#             "-"
#         )

#         action_text = action.get(
#             "action",
#             "No action was provided."
#         )

#         reason = action.get(
#             "reason",
#             ""
#         )

#         related_rules = action.get(
#             "related_rule_ids",
#             []
#         )

#         related_html = ""

#         if related_rules:
#             related_html = (
#                 "<p><strong>Related rules:</strong> "
#                 + safe_text(
#                     ", ".join(related_rules)
#                 )
#                 + "</p>"
#             )

#         reason_html = ""

#         if reason:
#             reason_html = (
#                 "<p><strong>Reason:</strong> "
#                 + safe_text(reason)
#                 + "</p>"
#             )

#         html_parts.append(
#             f"""
#             <div class="action-card">
#                 <div class="action-priority">
#                     Priority {safe_text(priority)}
#                 </div>

#                 <h3>{safe_text(action_text)}</h3>

#                 {reason_html}
#                 {related_html}
#             </div>
#             """
#         )

#     return "\n".join(
#         html_parts
#     )


# def render_owasp_findings(
#     ai_report: dict
# ) -> str:
#     """
#     Converts the AI OWASP-aligned findings into HTML.
#     """

#     key_findings = ai_report.get(
#         "key_findings",
#         []
#     )

#     if not key_findings:
#         return """
#         <p class="empty-message">
#             No OWASP-aligned explanations were generated.
#         </p>
#         """

#     html_parts = []

#     for finding in key_findings:
#         owasp = finding.get(
#             "owasp",
#             "OWASP mapping unavailable"
#         )

#         if not str(owasp).lower().startswith(
#             "owasp"
#         ):
#             owasp = f"OWASP {owasp}"

#         finding_text = finding.get(
#             "finding",
#             "No finding description was generated."
#         )

#         details = finding.get(
#             "details",
#             "No additional details were generated."
#         )

#         verification = finding.get(
#             "verification",
#             "Manual verification is recommended."
#         )

#         html_parts.append(
#             f"""
#             <article class="owasp-card">
#                 <h3>{safe_text(owasp)}</h3>

#                 <p>
#                     <strong>Finding:</strong>
#                     {safe_text(finding_text)}
#                 </p>

#                 <p>
#                     <strong>Details:</strong>
#                     {safe_text(details)}
#                 </p>

#                 <p>
#                     <strong>Verification:</strong>
#                     {safe_text(verification)}
#                 </p>
#             </article>
#             """
#         )

#     return "\n".join(
#         html_parts
#     )


# def render_technical_findings(
#     findings: list[Finding]
# ) -> str:
#     """
#     Converts every raw technical finding into table rows.
#     """

#     if not findings:
#         return """
#         <tr>
#             <td colspan="6">
#                 No technical findings were detected.
#             </td>
#         </tr>
#         """

#     rows = []

#     for index, finding in enumerate(
#         findings,
#         start=1
#     ):
#         risk_class = get_risk_class(
#             finding.risk
#         )

#         evidence = safe_text(
#             finding.evidence
#         )

#         details_html = f"""
#         <details>
#             <summary>View details</summary>

#             <p>
#                 <strong>Evidence:</strong>
#             </p>

#             <pre>{evidence}</pre>
#         </details>
#         """

#         rows.append(
#             f"""
#             <tr>
#                 <td>{index}</td>

#                 <td>
#                     <strong>
#                         {safe_text(finding.name)}
#                     </strong>

#                     {details_html}
#                 </td>

#                 <td>
#                     {safe_text(finding.category)}
#                 </td>

#                 <td>
#                     <span class="risk-badge {risk_class}">
#                         {safe_text(finding.risk)}
#                     </span>
#                 </td>

#                 <td>
#                     {safe_text(finding.confidence)}
#                 </td>

#                 <td>
#                     {safe_text(finding.owasp)}
#                     <br>
#                     <small>
#                         {safe_text(finding.rule_id)}
#                     </small>
#                 </td>
#             </tr>
#             """
#         )

#     return "\n".join(
#         rows
#     )


# def build_html_report(
#     target: str,
#     findings: list[Finding],
#     risk_summary: dict,
#     ai_report: dict
# ) -> str:
#     """
#     Builds a complete manager-friendly HTML report.

#     The report remains in memory and is not saved.
#     """

#     ai_report = ai_report or {}

#     executive_summary = ai_report.get(
#         "executive_summary",
#         (
#             "The AI executive summary was unavailable. "
#             "Refer to the technical findings below."
#         )
#     )

#     overall_assessment = ai_report.get(
#         "overall_assessment",
#         (
#             "The overall assessment was unavailable. "
#             "The deterministic risk summary remains valid."
#         )
#     )

#     limitations = ai_report.get(
#         "limitations",
#         (
#             "OWASPScan performs limited external and "
#             "non-destructive security observations."
#         )
#     )

#     conclusion = ai_report.get(
#         "conclusion",
#         (
#             "Review the identified findings and verify "
#             "the affected configurations manually."
#         )
#     )

#     overall_rating = risk_summary.get(
#         "overall_rating",
#         "Unknown"
#     )

#     total_score = risk_summary.get(
#         "total_score",
#         0
#     )

#     average_score = risk_summary.get(
#         "average_score",
#         0
#     )

#     try:
#         total_score_display = f"{float(total_score):.2f}"
#     except (TypeError, ValueError):
#         total_score_display = str(total_score)

#     try:
#         average_score_display = f"{float(average_score):.2f}"
#     except (TypeError, ValueError):
#         average_score_display = str(average_score)

#         critical_count = count_risk(
#             findings,
#             "Critical"
#         )

#     high_count = count_risk(
#         findings,
#         "High"
#     )

#     medium_count = count_risk(
#         findings,
#         "Medium"
#     )

#     low_count = count_risk(
#         findings,
#         "Low"
#     )

#     info_count = count_risk(
#         findings,
#         "Info"
#     )

#     rating_class = get_risk_class(
#         overall_rating
#     )

#     recommended_actions_html = (
#         render_recommended_actions(
#             ai_report
#         )
#     )

#     owasp_findings_html = (
#         render_owasp_findings(
#             ai_report
#         )
#     )

#     technical_findings_html = (
#         render_technical_findings(
#             findings
#         )
#     )

#     scan_time = datetime.now().strftime(
#         "%Y-%m-%d %H:%M:%S"
#     )

#     return f"""<!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">

#     <meta
#         name="viewport"
#         content="width=device-width, initial-scale=1.0"
#     >

#     <title>OWASPScan Security Assessment</title>

#     <style>
#         * {{
#             box-sizing: border-box;
#         }}

#         body {{
#             margin: 0;
#             background: #eef3f8;
#             color: #1f2937;
#             font-family:
#                 Arial,
#                 Helvetica,
#                 sans-serif;
#             line-height: 1.6;
#         }}

#         .container {{
#             width: min(1200px, 94%);
#             margin: 30px auto;
#         }}

#         .report-header {{
#             padding: 30px;
#             background: linear-gradient(135deg, #ffffff, #f7fbff);
#             border: 1px solid #d9e2ec;
#             border-top: 6px solid #2f6fad;
#             border-radius: 10px;
#             box-shadow: 0 4px 14px rgba(0, 0, 0, 0.05);
#         }}

#         .report-header h1 {{
#             margin: 0 0 8px 0;
#             font-size: 30px;
#         }}

#         .report-subtitle {{
#             margin: 0;
#             color: #52606d;
#         }}

#         .report-information {{
#             display: grid;
#             grid-template-columns:
#                 repeat(auto-fit, minmax(220px, 1fr));
#             gap: 12px;
#             margin-top: 24px;
#         }}

#         .information-item {{
#             padding: 12px;
#             background: #f8fbff;
#             border: 1px solid #d9e2ec;
#             border-radius: 6px;
#         }}

#         section {{
#             margin-top: 24px;
#             padding: 24px;
#             background: #ffffff;
#             border: 1px solid #d9e2ec;
#             border-radius: 10px;
#             box-shadow: 0 3px 10px rgba(0, 0, 0, 0.04);
#         }}

#         section h2 {{
#             margin-top: 0;
#             padding-bottom: 10px;
#             border-bottom: 2px solid #2f6fad;
#             color: #1f3c5b;
#             font-size: 22px;
#         }}

#         .summary-grid {{
#             display: grid;
#             grid-template-columns:
#                 repeat(auto-fit, minmax(160px, 1fr));
#             gap: 15px;
#         }}

#         .summary-card {{
#             padding: 18px;
#             text-align: center;
#             border: 1px solid #d9e2ec;
#             border-radius: 8px;
#             background: #f8fbff;
#         }}

#         .summary-card strong {{
#             display: block;
#             margin-bottom: 8px;
#             font-size: 14px;
#             color: #486581;
#         }}

#         .summary-value {{
#             font-size: 24px;
#             font-weight: bold;
#             color: #102a43;
#             word-break: break-word;
#         }}

#         .risk-badge {{
#             display: inline-block;
#             min-width: 85px;
#             padding: 8px 12px;
#             text-align: center;
#             border-radius: 6px;
#             font-weight: bold;
#         }}

#         .risk-high {{
#             color: #ffffff;
#             background: #b42318;
#         }}

#         .risk-medium {{
#             color: #222222;
#             background: #f5c542;
#         }}

#         .risk-low {{
#             color: #ffffff;
#             background: #666666;
#         }}

#         .action-card,
#         .owasp-card {{
#             margin-bottom: 16px;
#             padding: 18px;
#             border: 1px solid #d9e2ec;
#             border-left: 5px solid #2f6fad;
#             border-radius: 8px;
#             background: #f9fbfd;
#         }}

#         .action-card h3,
#         .owasp-card h3 {{
#             margin-top: 0;
#         }}

#         .action-priority {{
#             display: inline-block;
#             margin-bottom: 8px;
#             padding: 4px 8px;
#             border-radius: 4px;
#             background: #e5e5e5;
#             font-weight: bold;
#         }}

#         .table-wrapper {{
#             width: 100%;
#             overflow-x: auto;
#         }}

#         table {{
#             width: 100%;
#             border-collapse: collapse;
#             font-size: 14px;
#         }}

#         th,
#         td {{
#             padding: 12px;
#             border: 1px solid #dddddd;
#             text-align: left;
#             vertical-align: top;
#         }}

#         th {{
#             background: #eaf2fb;
#             color: #1f3c5b;
#         }}

#         tr:nth-child(even) {{
#             background: #f9fbfd;
#         }}

#         details {{
#             margin-top: 10px;
#         }}

#         summary {{
#             cursor: pointer;
#             font-weight: bold;
#         }}

#         pre {{
#             padding: 12px;
#             overflow-x: auto;
#             white-space: pre-wrap;
#             word-wrap: break-word;
#             border: 1px solid #d9e2ec;
#             border-radius: 4px;
#             background: #f4f7fa;
#             font-family:
#                 Consolas,
#                 Monaco,
#                 monospace;
#             font-size: 12px;
#         }}

#         .empty-message {{
#             color: #666666;
#             font-style: italic;
#         }}

#         .report-footer {{
#             margin-top: 24px;
#             padding: 20px;
#             text-align: center;
#             color: #666666;
#             font-size: 13px;
#         }}

#         @media print {{
#             body {{
#                 background: #ffffff;
#             }}

#             .container {{
#                 width: 100%;
#                 margin: 0;
#             }}

#             section,
#             .report-header {{
#                 border: none;
#                 box-shadow: none;
#                 break-inside: avoid;
#             }}

#             details {{
#                 display: block;
#             }}

#             details > * {{
#                 display: block;
#             }}
#         }}
#     </style>
# </head>

# <body>
#     <main class="container">
#         <header class="report-header">
#             <h1>OWASPScan Security Assessment</h1>

#             <p class="report-subtitle">
#                 External Web Security Misconfiguration Report
#             </p>

#             <div class="report-information">
#                 <div class="information-item">
#                     <strong>Target</strong>
#                     <br>
#                     {safe_text(target)}
#                 </div>

#                 <div class="information-item">
#                     <strong>Scan time</strong>
#                     <br>
#                     {safe_text(scan_time)}
#                 </div>

#                 <div class="information-item">
#                     <strong>Total findings</strong>
#                     <br>
#                     {len(findings)}
#                 </div>
#             </div>
#         </header>

#         <section>
#             <h2>Risk Summary</h2>

#             <div class="summary-grid">
#                 <div class="summary-card">
#                     <strong>Overall rating</strong>

#                     <span class="risk-badge {rating_class}">
#                         {safe_text(overall_rating)}
#                     </span>
#                 </div>

#                 <div class="summary-card">
#                     <strong>Total risk score</strong>

#                     <div class="summary-value">
#                         {safe_text(total_score_display)}
#                     </div>
#                 </div>

#                 <div class="summary-card">
#                     <strong>Average score</strong>

#                     <div class="summary-value">
#                         {safe_text(average_score_display)}
#                     </div>
#                 </div>

#                 <div class="summary-card">
#                     <strong>Critical / High</strong>

#                     <div class="summary-value">
#                         {critical_count + high_count}
#                     </div>
#                 </div>

#                 <div class="summary-card">
#                     <strong>Medium</strong>

#                     <div class="summary-value">
#                         {medium_count}
#                     </div>
#                 </div>

#                 <div class="summary-card">
#                     <strong>Low / Informational</strong>

#                     <div class="summary-value">
#                         {low_count + info_count}
#                     </div>
#                 </div>
#             </div>
#         </section>

#         <section>
#             <h2>Executive Summary</h2>

#             <p>
#                 {safe_text(executive_summary)}
#             </p>
#         </section>

#         <section>
#             <h2>Overall Assessment</h2>

#             <p>
#                 {safe_text(overall_assessment)}
#             </p>
#         </section>

#         <section>
#             <h2>Recommended Actions</h2>

#             {recommended_actions_html}
#         </section>

#         <section>
#             <h2>OWASP-Aligned Findings</h2>

#             {owasp_findings_html}
#         </section>

#         <section>
#             <h2>Technical Findings</h2>

#             <div class="table-wrapper">
#                 <table>
#                     <thead>
#                         <tr>
#                             <th>#</th>
#                             <th>Finding</th>
#                             <th>Category</th>
#                             <th>Risk</th>
#                             <th>Confidence</th>
#                             <th>OWASP / Rule</th>
#                         </tr>
#                     </thead>

#                     <tbody>
#                         {technical_findings_html}
#                     </tbody>
#                 </table>
#             </div>
#         </section>

#         <section>
#             <h2>Scan Limitations</h2>

#             <p>
#                 {safe_text(limitations)}
#             </p>
#         </section>

#         <section>
#             <h2>Conclusion</h2>

#             <p>
#                 {safe_text(conclusion)}
#             </p>
#         </section>

#         <footer class="report-footer">
#             Generated by OWASPScan.
#             This report contains external security observations
#             and does not confirm exploitability.
#         </footer>
#     </main>
# </body>
# </html>
# """


# def start_html_server(
#     html_content: str
# ) -> Tuple[
#     ThreadingHTTPServer,
#     str
# ]:
#     """
#     Serves the HTML report directly from memory.

#     No HTML file is created.
#     """

#     html_bytes = html_content.encode(
#         "utf-8"
#     )

#     class ReportHandler(
#         BaseHTTPRequestHandler
#     ):
#         def do_GET(self) -> None:
#             if self.path not in [
#                 "/",
#                 "/report"
#             ]:
#                 self.send_error(
#                     404
#                 )

#                 return

#             self.send_response(
#                 200
#             )

#             self.send_header(
#                 "Content-Type",
#                 "text/html; charset=utf-8"
#             )

#             self.send_header(
#                 "Content-Length",
#                 str(len(html_bytes))
#             )

#             self.send_header(
#                 "Cache-Control",
#                 "no-store"
#             )

#             self.end_headers()

#             self.wfile.write(
#                 html_bytes
#             )

#         def log_message(
#             self,
#             format_string: str,
#             *args
#         ) -> None:
#             return

#     server = ThreadingHTTPServer(
#         (
#             "127.0.0.1",
#             0
#         ),
#         ReportHandler
#     )

#     server_thread = threading.Thread(
#         target=server.serve_forever,
#         daemon=True
#     )

#     server_thread.start()

#     host, port = server.server_address

#     report_link = (
#         f"http://{host}:{port}/"
#     )

#     return (
#         server,
#         report_link
#     )


# def generate_html_report(
#     target: str,
#     findings: list[Finding],
#     risk_summary: dict,
#     ai_report: dict
# ) -> Tuple[
#     Optional[ThreadingHTTPServer],
#     Optional[str]
# ]:
#     """
#     Builds and serves the HTML report directly from memory.
#     """

#     html_content = build_html_report(
#         target=target,
#         findings=findings,
#         risk_summary=risk_summary,
#         ai_report=ai_report or {}
#     )

#     return start_html_server(
#         html_content
#     )







from datetime import datetime
from html import escape
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer
)
import threading
from typing import Optional, Tuple

from scanner.models import Finding


def safe_text(
    value
) -> str:
    """
    Converts report data into safely escaped HTML text.
    """

    if value is None:
        return ""

    return escape(
        str(value),
        quote=True
    )


def format_score(
    value
) -> str:
    """
    Formats numeric risk scores to two decimal places.
    """

    try:
        return f"{float(value):.2f}"

    except (
        TypeError,
        ValueError
    ):
        return safe_text(
            value
        )


def count_risk(
    findings: list[Finding],
    risk: str
) -> int:
    """
    Counts findings matching the supplied risk level.
    """

    return sum(
        1
        for finding in findings
        if finding.risk == risk
    )


def get_risk_class(
    risk: str
) -> str:
    """
    Returns the CSS class used for a risk level.
    """

    risk_value = str(
        risk
    ).strip().lower()

    if risk_value in (
        "critical",
        "high"
    ):
        return "risk-high"

    if risk_value == "medium":
        return "risk-medium"

    return "risk-low"


def format_owasp_title(
    owasp
) -> str:
    """
    Ensures that OWASP is written before the mapping.
    """

    owasp_text = str(
        owasp or ""
    ).strip()

    if not owasp_text:
        return "OWASP mapping unavailable"

    if owasp_text.lower().startswith(
        "owasp"
    ):
        return owasp_text

    return f"OWASP {owasp_text}"


def render_recommended_actions(
    ai_report: dict
) -> str:
    """
    Converts AI recommended actions into HTML.
    """

    actions = ai_report.get(
        "recommended_actions",
        []
    )

    if not isinstance(
        actions,
        list
    ) or not actions:
        return """
        <p class="empty-message">
            No recommended actions were generated.
        </p>
        """

    html_parts = []

    for action in actions:
        if isinstance(
            action,
            str
        ):
            html_parts.append(
                f"""
                <article class="action-card">
                    <p>{safe_text(action)}</p>
                </article>
                """
            )

            continue

        if not isinstance(
            action,
            dict
        ):
            continue

        priority = action.get(
            "priority",
            "-"
        )

        action_text = action.get(
            "action",
            "No action was provided."
        )

        reason = action.get(
            "reason",
            ""
        )

        related_rules = action.get(
            "related_rule_ids",
            []
        )

        reason_html = ""

        if reason:
            reason_html = f"""
            <p>
                <strong>Reason:</strong>
                {safe_text(reason)}
            </p>
            """

        related_rules_html = ""

        if (
            isinstance(
                related_rules,
                list
            )
            and related_rules
        ):
            related_rules_html = f"""
            <p>
                <strong>Related rules:</strong>
                {safe_text(", ".join(related_rules))}
            </p>
            """

        html_parts.append(
            f"""
            <article class="action-card">
                <span class="priority-label">
                    Priority {safe_text(priority)}
                </span>

                <h3>
                    {safe_text(action_text)}
                </h3>

                {reason_html}
                {related_rules_html}
            </article>
            """
        )

    if not html_parts:
        return """
        <p class="empty-message">
            No recommended actions were generated.
        </p>
        """

    return "\n".join(
        html_parts
    )


def render_owasp_findings(
    ai_report: dict
) -> str:
    """
    Converts AI OWASP-aligned findings into HTML.
    """

    key_findings = ai_report.get(
        "key_findings",
        []
    )

    if not isinstance(
        key_findings,
        list
    ) or not key_findings:
        return """
        <p class="empty-message">
            No OWASP-aligned explanations were generated.
        </p>
        """

    html_parts = []

    for finding in key_findings:
        if not isinstance(
            finding,
            dict
        ):
            continue

        owasp = format_owasp_title(
            finding.get(
                "owasp",
                ""
            )
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
            "Manual verification is recommended."
        )

        html_parts.append(
            f"""
            <article class="owasp-card">
                <h3>
                    {safe_text(owasp)}
                </h3>

                <p>
                    <strong>Finding:</strong>
                    {safe_text(finding_text)}
                </p>

                <p>
                    <strong>Details:</strong>
                    {safe_text(details)}
                </p>

                <p>
                    <strong>Verification:</strong>
                    {safe_text(verification)}
                </p>
            </article>
            """
        )

    if not html_parts:
        return """
        <p class="empty-message">
            No OWASP-aligned explanations were generated.
        </p>
        """

    return "\n".join(
        html_parts
    )


def render_technical_findings(
    findings: list[Finding]
) -> str:
    """
    Converts raw technical findings into HTML table rows.
    """

    if not findings:
        return """
        <tr>
            <td colspan="6">
                No technical findings were detected.
            </td>
        </tr>
        """

    rows = []

    for index, finding in enumerate(
        findings,
        start=1
    ):
        risk_class = get_risk_class(
            finding.risk
        )

        evidence = safe_text(
            finding.evidence
        )

        details_html = f"""
        <details>
            <summary>
                View technical evidence
            </summary>

            <pre>{evidence}</pre>
        </details>
        """

        rows.append(
            f"""
            <tr>
                <td>
                    {index}
                </td>

                <td>
                    <strong>
                        {safe_text(finding.name)}
                    </strong>

                    {details_html}
                </td>

                <td>
                    {safe_text(finding.category)}
                </td>

                <td>
                    <span class="risk-badge {risk_class}">
                        {safe_text(finding.risk)}
                    </span>
                </td>

                <td>
                    {safe_text(finding.confidence)}
                </td>

                <td>
                    {safe_text(
                        format_owasp_title(
                            finding.owasp
                        )
                    )}

                    <br>

                    <small class="rule-id">
                        {safe_text(finding.rule_id)}
                    </small>
                </td>
            </tr>
            """
        )

    return "\n".join(
        rows
    )


def build_html_report(
    target: str,
    findings: list[Finding],
    risk_summary: dict,
    ai_report: dict
) -> str:
    """
    Builds the complete manager-friendly HTML report.

    The report remains in memory and is not saved.
    """

    if not isinstance(
        ai_report,
        dict
    ):
        ai_report = {}

    executive_summary = ai_report.get(
        "executive_summary",
        (
            "The AI executive summary was unavailable. "
            "Refer to the technical findings below."
        )
    )

    overall_assessment = ai_report.get(
        "overall_assessment",
        (
            "The AI overall assessment was unavailable. "
            "The deterministic risk summary remains valid."
        )
    )

    limitations = ai_report.get(
        "limitations",
        (
            "OWASPScan performs limited external and "
            "non-destructive security observations."
        )
    )

    conclusion = ai_report.get(
        "conclusion",
        (
            "Review the identified findings and verify "
            "the affected configurations manually."
        )
    )

    overall_rating = risk_summary.get(
        "overall_rating",
        "Unknown"
    )

    total_score_display = format_score(
        risk_summary.get(
            "total_score",
            0
        )
    )

    average_score_display = format_score(
        risk_summary.get(
            "average_score",
            0
        )
    )

    critical_count = count_risk(
        findings,
        "Critical"
    )

    high_count = count_risk(
        findings,
        "High"
    )

    medium_count = count_risk(
        findings,
        "Medium"
    )

    low_count = count_risk(
        findings,
        "Low"
    )

    info_count = count_risk(
        findings,
        "Info"
    )

    rating_class = get_risk_class(
        overall_rating
    )

    recommended_actions_html = (
        render_recommended_actions(
            ai_report
        )
    )

    owasp_findings_html = (
        render_owasp_findings(
            ai_report
        )
    )

    technical_findings_html = (
        render_technical_findings(
            findings
        )
    )

    scan_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>OWASPScan Security Assessment</title>

    <style>
        :root {{
            --page-background: #edf3f8;
            --surface: #ffffff;
            --surface-soft: #f7fafc;
            --primary: #2f6fad;
            --primary-dark: #1f4f7a;
            --primary-soft: #e9f2fb;
            --text: #1f2937;
            --text-muted: #52606d;
            --border: #d7e0e8;
            --high: #c0392b;
            --medium: #f0c419;
            --low: #6b7280;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: var(--page-background);
            color: var(--text);
            font-family:
                Arial,
                Helvetica,
                sans-serif;
            line-height: 1.6;
        }}

        .container {{
            width: min(1200px, 94%);
            margin: 30px auto;
        }}

        .report-header {{
            padding: 32px;
            background:
                linear-gradient(
                    135deg,
                    #ffffff 0%,
                    #f4f9fe 100%
                );
            border: 1px solid var(--border);
            border-top: 6px solid var(--primary);
            border-radius: 12px;
            box-shadow:
                0 5px 16px
                rgba(31, 79, 122, 0.08);
        }}

        .report-header h1 {{
            margin: 0 0 8px 0;
            color: var(--primary-dark);
            font-size: 31px;
        }}

        .report-subtitle {{
            margin: 0;
            color: var(--text-muted);
            font-size: 17px;
        }}

        .report-information {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(220px, 1fr)
                );
            gap: 14px;
            margin-top: 26px;
        }}

        .information-item {{
            padding: 14px;
            background: rgba(255, 255, 255, 0.75);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        .information-item strong {{
            color: var(--primary-dark);
        }}

        section {{
            margin-top: 24px;
            padding: 25px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 11px;
            box-shadow:
                0 3px 12px
                rgba(31, 79, 122, 0.05);
        }}

        section h2 {{
            margin-top: 0;
            padding-bottom: 10px;
            color: var(--primary-dark);
            border-bottom: 2px solid var(--primary);
            font-size: 22px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(155px, 1fr)
                );
            gap: 15px;
        }}

        .summary-card {{
            min-width: 0;
            padding: 18px;
            text-align: center;
            background:
                linear-gradient(
                    180deg,
                    #ffffff 0%,
                    #f5f9fd 100%
                );
            border: 1px solid var(--border);
            border-radius: 9px;
        }}

        .summary-card strong {{
            display: block;
            margin-bottom: 10px;
            color: #486581;
            font-size: 14px;
        }}

        .summary-value {{
            max-width: 100%;
            color: #102a43;
            font-size: 24px;
            font-weight: bold;
            overflow-wrap: anywhere;
        }}

        .risk-badge {{
            display: inline-block;
            min-width: 85px;
            padding: 8px 12px;
            text-align: center;
            border-radius: 6px;
            font-weight: bold;
        }}

        .risk-high {{
            color: #ffffff;
            background: var(--high);
        }}

        .risk-medium {{
            color: #2d2a26;
            background: var(--medium);
        }}

        .risk-low {{
            color: #ffffff;
            background: var(--low);
        }}

        .action-card,
        .owasp-card {{
            margin-bottom: 16px;
            padding: 19px;
            background: var(--surface-soft);
            border: 1px solid var(--border);
            border-left: 5px solid var(--primary);
            border-radius: 8px;
        }}

        .action-card:last-child,
        .owasp-card:last-child {{
            margin-bottom: 0;
        }}

        .action-card h3,
        .owasp-card h3 {{
            margin: 8px 0 10px 0;
            color: var(--primary-dark);
        }}

        .priority-label {{
            display: inline-block;
            padding: 5px 9px;
            background: var(--primary-soft);
            color: var(--primary-dark);
            border: 1px solid #c6dbee;
            border-radius: 5px;
            font-size: 13px;
            font-weight: bold;
        }}

        .table-wrapper {{
            width: 100%;
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        table {{
            width: 100%;
            min-width: 900px;
            border-collapse: collapse;
            font-size: 14px;
        }}

        th,
        td {{
            padding: 13px;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
        }}

        th {{
            color: var(--primary-dark);
            background: var(--primary-soft);
        }}

        tr:nth-child(even) {{
            background: #f9fbfd;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        details {{
            margin-top: 10px;
        }}

        summary {{
            color: var(--primary-dark);
            cursor: pointer;
            font-weight: bold;
        }}

        pre {{
            padding: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: #f1f5f9;
            color: #273444;
            font-family:
                Consolas,
                Monaco,
                monospace;
            font-size: 12px;
        }}

        .rule-id {{
            color: var(--text-muted);
        }}

        .empty-message {{
            color: var(--text-muted);
            font-style: italic;
        }}

        .report-footer {{
            margin-top: 24px;
            padding: 20px;
            color: var(--text-muted);
            text-align: center;
            font-size: 13px;
        }}

        @media screen and (max-width: 700px) {{
            .container {{
                width: 96%;
                margin: 15px auto;
            }}

            .report-header,
            section {{
                padding: 18px;
            }}

            .report-header h1 {{
                font-size: 25px;
            }}

            .summary-value {{
                font-size: 21px;
            }}
        }}

        @media print {{
            body {{
                background: #ffffff;
            }}

            .container {{
                width: 100%;
                margin: 0;
            }}

            section,
            .report-header {{
                border: 1px solid #dddddd;
                box-shadow: none;
                break-inside: avoid;
            }}

            details {{
                display: block;
            }}

            details > * {{
                display: block;
            }}
        }}
    </style>
</head>

<body>
    <main class="container">
        <header class="report-header">
            <h1>
                OWASPScan Security Assessment
            </h1>

            <p class="report-subtitle">
                External Web Security Misconfiguration Report
            </p>

            <div class="report-information">
                <div class="information-item">
                    <strong>Target</strong>

                    <br>

                    {safe_text(target)}
                </div>

                <div class="information-item">
                    <strong>Scan time</strong>

                    <br>

                    {safe_text(scan_time)}
                </div>

                <div class="information-item">
                    <strong>Total findings</strong>

                    <br>

                    {len(findings)}
                </div>
            </div>
        </header>

        <section>
            <h2>
                Risk Summary
            </h2>

            <div class="summary-grid">
                <div class="summary-card">
                    <strong>
                        Overall rating
                    </strong>

                    <span class="risk-badge {rating_class}">
                        {safe_text(overall_rating)}
                    </span>
                </div>

                <div class="summary-card">
                    <strong>
                        Total risk score
                    </strong>

                    <div class="summary-value">
                        {safe_text(total_score_display)}
                    </div>
                </div>

                <div class="summary-card">
                    <strong>
                        Average score
                    </strong>

                    <div class="summary-value">
                        {safe_text(average_score_display)}
                    </div>
                </div>

                <div class="summary-card">
                    <strong>
                        Critical / High
                    </strong>

                    <div class="summary-value">
                        {critical_count + high_count}
                    </div>
                </div>

                <div class="summary-card">
                    <strong>
                        Medium
                    </strong>

                    <div class="summary-value">
                        {medium_count}
                    </div>
                </div>

                <div class="summary-card">
                    <strong>
                        Low / Informational
                    </strong>

                    <div class="summary-value">
                        {low_count + info_count}
                    </div>
                </div>
            </div>
        </section>

        <section>
            <h2>
                Executive Summary
            </h2>

            <p>
                {safe_text(executive_summary)}
            </p>
        </section>

        <section>
            <h2>
                Overall Assessment
            </h2>

            <p>
                {safe_text(overall_assessment)}
            </p>
        </section>

        <section>
            <h2>
                Recommended Actions
            </h2>

            {recommended_actions_html}
        </section>

        <section>
            <h2>
                OWASP-Aligned Findings
            </h2>

            {owasp_findings_html}
        </section>

        <section>
            <h2>
                Technical Findings
            </h2>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Finding</th>
                            <th>Category</th>
                            <th>Risk</th>
                            <th>Confidence</th>
                            <th>OWASP / Rule</th>
                        </tr>
                    </thead>

                    <tbody>
                        {technical_findings_html}
                    </tbody>
                </table>
            </div>
        </section>

        <section>
            <h2>
                Scan Limitations
            </h2>

            <p>
                {safe_text(limitations)}
            </p>
        </section>

        <section>
            <h2>
                Conclusion
            </h2>

            <p>
                {safe_text(conclusion)}
            </p>
        </section>

        <footer class="report-footer">
            Generated by OWASPScan. This report contains
            external security observations and does not
            confirm exploitability.
        </footer>
    </main>
</body>
</html>
"""


def start_html_server(
    html_content: str
) -> Tuple[
    ThreadingHTTPServer,
    str
]:
    """
    Serves the HTML report directly from memory.

    No HTML file is created.
    """

    html_bytes = html_content.encode(
        "utf-8"
    )

    class ReportHandler(
        BaseHTTPRequestHandler
    ):
        def do_GET(
            self
        ) -> None:
            if self.path not in (
                "/",
                "/report"
            ):
                self.send_error(
                    404
                )

                return

            self.send_response(
                200
            )

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )

            self.send_header(
                "Content-Length",
                str(
                    len(
                        html_bytes
                    )
                )
            )

            self.send_header(
                "Cache-Control",
                "no-store"
            )

            self.end_headers()

            self.wfile.write(
                html_bytes
            )

        def log_message(
            self,
            format_string: str,
            *args
        ) -> None:
            return

    server = ThreadingHTTPServer(
        (
            "127.0.0.1",
            0
        ),
        ReportHandler
    )

    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )

    server_thread.start()

    host, port = server.server_address

    report_link = (
        f"http://{host}:{port}/"
    )

    return (
        server,
        report_link
    )


def generate_html_report(
    target: str,
    findings: list[Finding],
    risk_summary: dict,
    ai_report: dict
) -> Tuple[
    Optional[ThreadingHTTPServer],
    Optional[str]
]:
    """
    Builds and serves the manager-friendly HTML report.

    No JSON or HTML file is saved.
    """

    try:
        html_content = build_html_report(
            target=target,
            findings=findings,
            risk_summary=risk_summary,
            ai_report=ai_report or {}
        )

        return start_html_server(
            html_content
        )

    except Exception as error:
        print(
            "[!] HTML report generation failed: "
            f"{type(error).__name__}: {error}"
        )

        return (
            None,
            None
        )