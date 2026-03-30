import math as m

def ThreatScore(abuse_score,total_reports) :
    report_factor = m.log1p(total_reports) *10
    threat_score = (0.7*abuse_score) + (0.3*report_factor)
    return threat_score

def ConfidenceScore(total_reports, maxReports=1000) :
    confidence = (m.log1p(total_reports) / m.log1p(maxReports)) * 100
    return round(confidence, 2)

def classify_ip(threat_score, confidence):
    if threat_score < 30:
        return "Safe"
    
    elif 30 <= threat_score < 70:
        if confidence < 40:
            return "Suspicious"
        else:
            return "Likely Malicious"
    
    else:  # threat_score >= 70
        if confidence >= 50:
            return "Malicious"
        else:
            return "Suspicious"

def malcheck(abuse_score, total_reports):

    match abuse_score:
        case 0:
            a_status = "Safe"
        case score if score < 50:
            a_status = "Suspicious"
        case _:
            a_status = "Malicious"

    match total_reports:
        case reports if reports < 4:
            t_status = "Safe"
        case reports if reports < 25:
            t_status = "Suspicious"
        case _:
            t_status = "Malicious"

    match (a_status, t_status):
        case ("Safe", "Safe"):
            status = "Safe"
        case ("Safe", "Suspicious") | ("Suspicious", "Safe"):
            status = "Maybe Suspicious"
        case ("Suspicious", "Suspicious"):
            status = "Suspicious"
        case ("Safe", "Malicious") | ("Malicious", "Safe"):
            status = "Maybe Malicious"
        case ("Malicious", "Malicious"):
            status = "Malicious"
        case _:
            status = "Malicious"

    return a_status, t_status, status
