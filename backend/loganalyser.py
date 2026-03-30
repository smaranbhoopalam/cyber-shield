from logparser import extract_ips
from analyser import analyze_ip

def analyze_log(file):

    ips = extract_ips(file)

    results = {
        "Safe": [],
        "Suspicious": [],
        "Malicious": []
    }

    for ip in ips:
        data = analyze_ip(ip)

        verdict = data["verdict"]

        results[verdict].append(data)

    return results