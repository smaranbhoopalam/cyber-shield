import socket
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, UploadFile, File, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tempfile
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env.local"))
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from supabase_client import supabase
import analyser
import loganalyser

app = FastAPI(title="CyberShield API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_user_id(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        user = supabase.auth.get_user(token)
        return user.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def extract_ip(input_value):
    try:
        # Normalize input
        input_value = input_value.strip()

        # Extract domain if URL
        if input_value.startswith("http"):
            domain = urlparse(input_value).netloc
        else:
            domain = input_value

        # Remove trailing dot (IMPORTANT)
        domain = domain.rstrip(".")

        # Resolve to IP
        ip = socket.gethostbyname(domain)
        return ip

    except Exception as e:
        print("Error resolving:", e)
        return None

import socket
from urllib.parse import urlparse

def extract_ip_from_url(url: str):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path

        # Clean domain (remove extra path junk)
        domain = domain.split("/")[0]

        ip = socket.gethostbyname(domain)
        return ip, None

    except Exception:
        # Instead of crashing → return error flag
        return None, "Invalid or suspicious domain"


class IPScanRequest(BaseModel):
    ip: str

class URLScanRequest(BaseModel):
    url: str

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scan/ip")
async def scan_ip(request: IPScanRequest) :
    import ipaddress
    try:
        ipaddress.ip_address(request.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    try:
        result = analyser.analyze_ip(request.ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    supabase.table("scan_results").insert({
        "scan_type": "ip",
        "target": request.ip,
        "verdict": result["verdict"],
        "abuse_score": result["abuse_score"],
        "vt_score": result["vt_score"],
        "final_score": result["final_score"],
        "details": result,
    }).execute()

    return result

@app.post("/scan/url")
async def scan_url(request: URLScanRequest):
    
    ip, error = extract_ip_from_url(request.url)

    if error:
        return {
            "url": request.url,
            "resolved_ip": None,
            "verdict": "Suspicious",
            "reason": error
        }

    try:
        result = analyser.analyze_ip(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Save to DB
    supabase.table("scan_results").insert({
        "scan_type": "url",
        "target": request.url,
        "verdict": result["verdict"],
        "abuse_score": result["abuse_score"],
        "vt_score": result["vt_score"],
        "final_score": result["final_score"],
        "details": result,
    }).execute()

    return {
        "url": request.url,
        "resolved_ip": ip,
        "analysis": result
    }


@app.post("/scan/log")
async def scan_log(
    file: UploadFile = File(...),
    user_id: str = Depends(get_user_id),
):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".log", delete=False
        ) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        results = loganalyser.analyze_log(tmp_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    records = []
    for verdict, ip_list in results.items():
        for item in ip_list:
            records.append({
                "user_id": user_id,
                "scan_type": "log",
                "target": item["ip"],
                "verdict": item["verdict"],
                "abuse_score": item.get("abuse_score"),
                "vt_score": item.get("vt_score"),
                "final_score": item.get("final_score"),
                "details": item,
            })
    if records:
        supabase.table("scan_results").insert(records).execute()

    return {
        "filename": file.filename,
        "results": results,
        "summary": {
            "total": sum(len(v) for v in results.values()),
            "safe": len(results.get("Safe", [])),
            "suspicious": len(results.get("Suspicious", [])),
            "malicious": len(results.get("Malicious", [])),
        },
    }


@app.post("/scan/capture")
async def scan_capture(user_id: str = Depends(get_user_id)):
    try:
        from scapy.all import sniff

        seen_ips: set = set()
        capture_results: list = []

        def process_packet(packet):
            if packet.haslayer("IP"):
                ip = packet["IP"].src
                if ip in seen_ips:
                    return
                seen_ips.add(ip)
                try:
                    result = analyser.analyze_ip(ip)
                    capture_results.append(result)
                except Exception:
                    pass

        sniff(prn=process_packet, count=100, timeout=60)

        records = [
            {
                "user_id": user_id,
                "scan_type": "capture",
                "target": item["ip"],
                "verdict": item["verdict"],
                "abuse_score": item.get("abuse_score"),
                "vt_score": item.get("vt_score"),
                "final_score": item.get("final_score"),
                "details": item,
            }
            for item in capture_results
        ]
        if records:
            supabase.table("scan_results").insert(records).execute()

        return {
            "results": capture_results,
            "summary": {
                "total": len(capture_results),
                "safe": sum(1 for r in capture_results if r["verdict"] == "Safe"),
                "suspicious": sum(
                    1 for r in capture_results if r["verdict"] == "Suspicious"
                ),
                "malicious": sum(
                    1 for r in capture_results if r["verdict"] == "Malicious"
                ),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history")
async def get_history(user_id: str = Depends(get_user_id)):
    response = (
        supabase.table("scan_results")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    return response.data


@app.delete("/history/{scan_id}")
async def delete_history(scan_id: str, user_id: str = Depends(get_user_id)):
    supabase.table("scan_results").delete().eq("id", scan_id).eq(
        "user_id", user_id
    ).execute()
    return {"success": True}
