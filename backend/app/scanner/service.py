import ipaddress, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

SECURITY_HEADERS = {"Content-Security-Policy": 20, "X-Frame-Options": 15, "Strict-Transport-Security": 20, "X-Content-Type-Options": 10, "Referrer-Policy": 10}

def validate_public_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password: raise ValueError("Provide a valid public HTTP(S) URL.")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global: raise ValueError("Private, loopback, and reserved addresses cannot be scanned.")
    except socket.gaierror as error: raise ValueError("The hostname could not be resolved.") from error
    return value

def ssl_details(host: str, timeout: int) -> dict:
    if not host: return {"valid": False}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host,443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert=conn.getpeercert(); expires=datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                issuer=", ".join("=".join(x) for group in cert.get("issuer",[]) for x in group)
                return {"valid": expires > datetime.now(timezone.utc), "issuer": issuer, "expires": expires.isoformat(), "tls_version": conn.version(), "cipher": conn.cipher()[0]}
    except (OSError, ssl.SSLError, KeyError, ValueError): return {"valid": False}

def scan(url: str, timeout: int) -> dict:
    validate_public_url(url)
    response=requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"VulnScanLite/1.0 (passive security assessment)"})
    final_url=response.url; headers={name: {"present": name.lower() in {k.lower() for k in response.headers}, "impact": f"+{weight}" if name.lower() in {k.lower() for k in response.headers} else f"-{weight}"} for name,weight in SECURITY_HEADERS.items()}
    soup=BeautifulSoup(response.text[:1_000_000], "html.parser"); generator=(soup.find("meta", attrs={"name":"generator"}) or {}).get("content","")
    cms=next((x for x in ["WordPress","Drupal","Joomla","Ghost"] if x.lower() in generator.lower() or x.lower() in response.text[:1_000_000].lower()), None)
    passed=sum(item["present"] for item in headers.values()); total=len(headers); score=max(0, min(100, 50 + sum(weight if headers[name]["present"] else -weight for name,weight in SECURITY_HEADERS.items())))
    grade=next(grade for threshold,grade in [(90,"A"),(80,"B"),(70,"C"),(60,"D"),(0,"F")] if score>=threshold)
    return {"url":final_url,"score":score,"grade":grade,"risk_level":"Low" if score>=80 else "Medium" if score>=60 else "High","summary":{"total":total,"passed":passed,"failed":total-passed},"headers":headers,"ssl":ssl_details(urlparse(final_url).hostname,timeout) if urlparse(final_url).scheme=="https" else {"valid":False},"cms":{"name":cms,"version":generator or None},"server":{"server":response.headers.get("Server"),"powered_by":response.headers.get("X-Powered-By")},"completed_at":datetime.now(timezone.utc).isoformat()}
