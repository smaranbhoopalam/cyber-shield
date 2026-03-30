def virusCheck(stats) :

    attributes = stats.get("data", {}).get("attributes", {})

    user_votes = attributes.get("total_votes", {})
    uharmless = user_votes.get("harmless", 0)
    umalicious = user_votes.get("malicious", 0)

    engine_stats = attributes.get("last_analysis_stats", {})
    malicious = engine_stats.get("malicious", 0)
    suspicious = engine_stats.get("suspicious", 0)
    undetected = engine_stats.get("undetected", 0)
    harmless = engine_stats.get("harmless", 0)

    reputation_score = attributes.get("reputation", 0)

    total_engines = malicious + suspicious + harmless + undetected
    total_votes = umalicious + uharmless

    mal_ratio = malicious / total_engines if total_engines else 0
    sus_ratio = suspicious / total_engines if total_engines else 0
    user_ratio = umalicious / total_votes if total_votes else 0

    rep_factor = min(abs(reputation_score) / 1000, 1) if reputation_score < 0 else 0

    score = (mal_ratio*60) + (sus_ratio*20) + (user_ratio*10) + (rep_factor*10)

    if score < 10:
        status = "Safe"
    elif score < 30:
        status = "Suspicious"
    else:
        status = "Malicious"

    return rep_factor, status, total_engines, total_votes, reputation_score, malicious, suspicious, harmless, umalicious, uharmless, score