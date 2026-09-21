from scanner.models import Finding


RISK_SCORES = {
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Info": 0
}


CONFIDENCE_MULTIPLIERS = {
    "Confirmed": 1.0,
    "Likely": 0.8,
    "Possible": 0.5,
    "Uncertain": 0.3,
    "Info": 0.0
}


def score_finding(finding: Finding) -> float:
    risk_score = RISK_SCORES.get(finding.risk, 0)
    confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0)

    score = risk_score * confidence_multiplier

    return round(score, 2)


def calculate_total_score(findings: list[Finding]) -> float:
    total_score = 0

    for finding in findings:
        total_score += score_finding(finding)
    
    return round(total_score,2)


def calculate_average_score(findings: list[Finding]) -> float:
    if not findings:
        return 0
    
    total_score = calculate_total_score(findings)
    average_score = total_score / len(findings)

    return average_score


def get_overall_rating(total_score: float) -> str:
    if total_score >= 30:
        return "Critical"
    if total_score >= 20:
        return "High"
    if total_score >= 10:
        return "Medium"
    if total_score >= 0:
        return "Low"
    
    return "Info"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key = score_finding, reverse = True)



def generate_risk_summary(findings: list[Finding]) -> str:
    total_score = calculate_total_score(findings)
    average_score = calculate_average_score(findings)
    overall_rating = get_overall_rating(total_score)

    return{
        "total_score": total_score,
        "average_score": average_score,
        "overall_rating": overall_rating,
        "total_findings": len(findings)
    }