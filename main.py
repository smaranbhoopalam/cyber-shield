import ipaddress
import malicioustracker as mal
import checkAbuseAPI as c
import checkVirusAPI as cv
import maltracker as mals
import unifiedScore as us

def main() :

    ip = input("Enter the IP Address you want to check : ")
    print("Validating the IP address...")
    ip = validate_ip(ip)

    print("Checking", ip)

    abuse_score, total_reports = c.checkAPI(ip) 
    a_status, t_status, status = mal.malcheck(abuse_score, total_reports)
    threat_score = mal.ThreatScore(abuse_score, total_reports)
    confidence = mal.ConfidenceScore(total_reports)

    verdict = mal.classify_ip(threat_score, confidence)

    print("\n-------------------------------------------------")
    print("               AbuseIDPB Analysis")
    print("Abuse Score:", abuse_score)
    print("Reports:", total_reports)
    print(f"AbuseScore Status: {a_status},\nTotalReports Status: {t_status}")
    print(f"The IP Address - {ip} is potentially {status}")
    print(f"Final Verdict calculated using a formula: {verdict}")
    print("-------------------------------------------------\n")


    stats = cv.checkAPI2(ip)
    rep_factor, status, engineVotes, userVotes, Reputation, EngMalVotes, EngSusVotes, EngHarmlessVotes, UMalVotes, UHarmlessVotes, score = mals.virusCheck(stats)

    print("-------------------------------------------------")                              
    print("               VirusTotal Analysis")
    print(f"Number of Engine Votes : {engineVotes}")
    print(f"    Malacious Reports : {EngMalVotes}")
    print(f"    Suspicious Reports : {EngSusVotes}")
    print(f"    Safe Reports : {EngHarmlessVotes}")
    print(f"Number of User Votes : {userVotes}")
    print(f"    Malacious Reports : {UMalVotes}")
    print(f"    Safe Reports : {UHarmlessVotes}")
    print(f"Reputation : {Reputation}")
    print(f"Reputation Factor : {rep_factor}")
    print(f"Final Verdict : {status}")
    print("-------------------------------------------------\n")

    print("Here is the Unified Decision from both APIs ")
    final_score = us.unified_score(abuse_score, total_reports, score)
    finalVerdict = us.final_verdict(final_score)
    print(f"The IP Address is {finalVerdict}")
    
    miti = mitigation(finalVerdict)
    print(f"Suggested Action to be taken : {miti}")

def validate_ip(a) :
    while True :
        try :
            ipaddress.ip_address(a)
            break
        except ValueError :
            print("Invalid IP Address. PLease Try Agian!")
            a = input("Enter a Valid IP Address: ")
    return a

def mitigation(status):
    if status == "Malicious":
        return "Block IP immediately"
    elif status == "Suspicious":
        return "Monitor activity"
    else:
        return "No action needed"

if __name__ == "__main__" :
    main()