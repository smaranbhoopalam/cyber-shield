import re
import ipaddress

def extract_ips(filename):
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    ips = set()

    with open(filename, "r") as f:
        for line in f:
            matches = re.findall(ip_pattern, line)

            for ip in matches:
                try:
                    ipaddress.ip_address(ip)  # validate
                    ips.add(ip)
                except ValueError:
                    pass  # ignore invalid IPs

    return list(ips)