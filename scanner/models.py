from dataclasses import dataclass

## Finding class for each issue or piece of information encountered
##Findings contain: category (scanner module that detected the issue), 
#                   name (exact weakness/vulnerability), 
#                   risk (low, medium, high, info), 
#                   evidence (evidence of the finding), 
#                   rule_id (check rules.py), 
#                   confidence (uncertain, possible, likely), 
#                   owasp (official owasp category)

@dataclass
class Finding:
    category: str
    name: str
    risk: str
    evidence: str
    rule_id: str = ""
    confidence: str = "Likely"
    owasp: str = ""

