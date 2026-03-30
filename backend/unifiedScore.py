import math

def unified_score(abuse_score, total_reports, score) :
    abuse_compo = abuse_score * 0.5
    
    report_factor = min(math.log1p(total_reports)*10, 100)
    report_compo = report_factor *0.2

    vt_compo = score *0.3

    final_score = abuse_compo + report_compo + vt_compo

    return round(final_score, 2)

def final_verdict(final_score) :
    if final_score < 20:
        return "Safe"
    elif final_score < 50:
        return "Suspicious"
    else:
        return "Malicious"