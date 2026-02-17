from asset import Asset
from vulnerability import Vulnerability

def should_ticket(asset: Asset, vuln: Vulnerability) -> bool:
    # Ignore closed / false positives if your dataset has status
    if (vuln.status or "").lower() in {"false_positive", "closed", "mitigated"}:
        return False

    # Derive severity from CVSS (v3-style ranges)
    try:
        score = float(vuln.cvss_score) if vuln.cvss_score is not None else None
    except (TypeError, ValueError):
        score = None

    if score is None:
        # If CVSS is missing/unparseable, don't auto-ticket by default
        # (You could choose to ticket if exploit_available/internet_exposed instead.)
        return False

    if score >= 9.0:
        sev = "critical"
    elif score >= 7.0:
        sev = "high"
    elif score >= 4.0:
        sev = "medium"
    else:
        sev = "low"

    # Ticket anything High/Critical
    if sev in {"critical", "high"}:
        return True

    # Escalate Medium if exploit available + prod
    if sev == "medium" and vuln.exploit_available and (asset.environment or "").lower() == "prod":
        return True

    return False
