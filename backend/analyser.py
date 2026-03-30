import checkAbuseAPI as c
import checkVirusAPI as cv
import maltracker as mals
import malicioustracker as mal
import unifiedScore as us

def analyze_ip(ip):

    # ── AbuseIPDB ──
    abuse_score, reports = c.checkAPI(ip)

    a_status, t_status, abuse_status = mal.malcheck(abuse_score, reports)
    threat_score = mal.ThreatScore(abuse_score, reports)
    threat_score = round(threat_score, 2)
    confidence = mal.ConfidenceScore(reports)
    confidence = round(confidence, 2)
    abuse_verdict = mal.classify_ip(threat_score, confidence)

    # ── VirusTotal ──
    vt_raw = cv.checkAPI2(ip)

    (
        rep_factor,
        vt_status,
        engineVotes,
        userVotes,
        reputation,
        eng_mal,
        eng_sus,
        eng_safe,
        u_mal,
        u_safe,
        vt_score
    ) = mals.virusCheck(vt_raw)

    # ── Final ──
    final_score = us.unified_score(abuse_score, reports, vt_score)
    final_verdict = us.final_verdict(final_score)

    if final_verdict == "Malicious":
        action = "Block IP immediately"
    elif final_verdict == "Suspicious":
        action = "Monitor activity"
    else:
        action = "No action needed"

    return {
        "ip": ip,

        "abuse_score": abuse_score,
        "vt_score": vt_score,
        "final_score": final_score,
        "verdict": final_verdict,

        "abuse_analysis": {
            "reports": reports,
            "threat_score": threat_score,
            "confidence": confidence,
            "status": abuse_status
        },

        "virus_total_analysis": {
            "engine_votes": engineVotes,
            "malicious": eng_mal,
            "suspicious": eng_sus,
            "safe": eng_safe,
            "reputation": reputation
        },

        "final_analysis": {
            "suggested_action": action
        }
    }