from dotenv import load_dotenv
import os
import requests
import json

load_dotenv(".env.local")
virus_apikey = os.getenv("VIRUS_TOTAL_API_KEY")

def checkAPI2(var2) :
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{var2}"

    header = {
        "x-apikey" : virus_apikey,
        "accept" : "application/json"
    }

    parameters = {
        "ip" : var2
    }

    response2 = requests.get(url, headers=header, params=parameters)
    decoderesponse = response2.json()

    return decoderesponse 

