from dotenv import load_dotenv
import os
import json
import requests

load_dotenv(".env.local")
abuse_apikey = os.getenv("ABUSE_IPDB_API_KEY")

def checkAPI(var) :
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key" : abuse_apikey,
        "Accept" : "application/json"
    }

    parameters = {
        "ipAddress" : var,
        "maxAgeinDays" : 90
    }

    response = requests.request(method='GET', url=url, headers=headers, params=parameters)
    decodedresponse = response.json()

    abuse_score = decodedresponse.get("data", {}).get("abuseConfidenceScore", {})
    total_reports = decodedresponse.get("data", {}).get("totalReports", {})

    return abuse_score, total_reports