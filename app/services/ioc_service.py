# ============================================================
# app/services/ioc_service.py — IOC Intelligence & Triage Engine
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides automated classification, threat intelligence enrichment,
# network OSINT, and risk scoring for Indicators of Compromise (IOCs)
# including IP addresses, Domains, URLs, and File Hashes (MD5/SHA256).
#
# WHY DO SOC ANALYSTS NEED THIS?
# ------------------------------
# When triaging security alerts, analysts spend valuable minutes manually
# pivoting across multiple tabs (VirusTotal, AbuseIPDB, URLhaus, Shodan).
# This service aggregates multi-source threat intelligence, resolves
# GeoIP/ASN network metadata, correlates with known threat actors, and
# computes a standardized risk verdict in a single view.
#
# PYTHON CONCEPTS COVERED:
# - Regular expressions (re module) for IOC pattern recognition
# - IP address parsing with the standard library ipaddress module
# - DNS resolution and reverse lookup with the socket module
# - Safe asynchronous/synchronous HTTP requests with httpx
# - Dynamic scoring algorithms and verdict classification
# ============================================================

import re
import socket
import ipaddress
from urllib.parse import urlparse
import httpx

from app.database import get_connection
from app.config import HTTP_TIMEOUT_SECONDS


# ============================================================
# IOC CLASSIFICATION LOGIC
# ============================================================

def classify_ioc(indicator: str) -> str:
    """
    Classify an indicator into its exact IOC type.
    
    Supported Types:
      - 'ipv4': Standard IPv4 address (e.g. 192.168.1.1, 185.220.101.5)
      - 'ipv6': Standard IPv6 address (e.g. 2001:db8::1)
      - 'md5': 32-character hexadecimal hash
      - 'sha1': 40-character hexadecimal hash
      - 'sha256': 64-character hexadecimal hash
      - 'url': Full URL with http/https scheme or resource path
      - 'domain': Fully Qualified Domain Name (FQDN)
      - 'unknown': Unrecognized indicator format
    """
    if not indicator or not isinstance(indicator, str):
        return "unknown"

    val = indicator.strip()

    # 1. Hashes (MD5: 32, SHA1: 40, SHA256: 64)
    if re.fullmatch(r"[a-fA-F0-9]{64}", val):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", val):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", val):
        return "md5"

    # 2. IP Addresses (IPv4 or IPv6)
    try:
        ip = ipaddress.ip_address(val)
        return "ipv4" if isinstance(ip, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        pass

    # 3. URLs
    if val.startswith("http://") or val.startswith("https://") or ("/" in val and not val.endswith("/")):
        return "url"

    # 4. Domains (e.g. evil-payload.ru, sub.domain.com)
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.fullmatch(domain_regex, val):
        return "domain"

    return "unknown"


# ============================================================
# OSINT ENRICHMENT HELPERS
# ============================================================

def enrich_ip(ip_str: str) -> dict:
    """
    Perform Network OSINT & GeoIP enrichment for an IP address.
    """
    result = {
        "indicator": ip_str,
        "type": "IP Address",
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "region": "Unknown",
        "isp": "Unknown ISP",
        "org": "Unknown Organization",
        "asn": "N/A",
        "reverse_dns": "None",
        "is_private": False,
        "is_bogon": False,
        "geo_flag": "🌐",
        "dns_status": "not_queried",
        "geoip_status": "not_queried",
    }

    # Check if private/loopback/bogon
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            result["is_private"] = True
            result["country"] = "Private / Internal Network"
            result["isp"] = "RFC1918 Private Subnet"
            result["org"] = "Internal Enterprise Network"
            result["geo_flag"] = "🛡️"
            return result
    except Exception:
        pass

    # Reverse DNS Lookup
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        result["reverse_dns"] = host
        result['dns_status'] = 'available'
    except Exception:
        result["reverse_dns"] = "No PTR Record"
        result['dns_status'] = 'unavailable'

    # Live GeoIP & ASN API Lookup (ip-api.com)
    result['geoip_status'] = 'unavailable'
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result['geoip_status'] = 'available'
                    result["country"] = data.get("country", "Unknown")
                    result["country_code"] = data.get("countryCode", "XX")
                    result["city"] = data.get("city", "Unknown")
                    result["region"] = data.get("regionName", "Unknown")
                    result["isp"] = data.get("isp", "Unknown ISP")
                    result["org"] = data.get("org", "Unknown Organization")
                    result["asn"] = data.get("as", "N/A")

                    # Map Country Flag Emoji
                    code = result["country_code"].upper()
                    if len(code) == 2 and code != "XX":
                        # Unicode Regional Indicator flag calculation
                        flag = "".join(chr(127397 + ord(char)) for char in code)
                        result["geo_flag"] = flag
    except httpx.TimeoutException:
        result['geoip_status'] = 'timeout'
    except Exception:
        result['geoip_status'] = 'unavailable'

    return result


def enrich_domain(domain_str: str) -> dict:
    """
    Perform DNS and network resolution for a domain.
    """
    result = {
        "indicator": domain_str,
        "type": "Domain Name",
        "resolved_ips": [],
        "mx_records": [],
        "primary_ip": None,
        "ip_enrichment": None,
        "dns_status": "not_queried",
    }

    # Resolve A records (IPv4)
    try:
        resolved = socket.gethostbyname_ex(domain_str)
        ips = resolved[2]
        result["resolved_ips"] = ips
        result['dns_status'] = 'available' if ips else 'unavailable'
        if ips:
            result["primary_ip"] = ips[0]
            result["ip_enrichment"] = enrich_ip(ips[0])
    except Exception:
        result["resolved_ips"] = []
        result['dns_status'] = 'unavailable'

    return result


def enrich_url(url_str: str) -> dict:
    """
    Extract domain and path metadata from a URL.
    """
    parsed = urlparse(url_str)
    domain = parsed.hostname or url_str
    path = parsed.path or "/"

    domain_data = enrich_domain(domain) if domain else {}
    return {
        "indicator": url_str,
        "type": "URL",
        "domain": domain,
        "path": path,
        "scheme": parsed.scheme or "http",
        "domain_enrichment": domain_data,
    }


def enrich_hash(hash_str: str, hash_type: str) -> dict:
    """
    Lookup file hash intelligence from local database and curated catalog.
    """
    clean_hash = hash_str.strip().lower()

    # Only verified standard test hashes are retained as local ground truth.
    if clean_hash in ("44d88612fea8a8f36de82e1278abb02f", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"):
        return {"hash_type": hash_type.upper(), "malware_family": "EICAR antivirus test file",
                "threat_actor": "N/A", "threat_type": "Benign security test", "threat_score": 0,
                "verdict": "CLEAN", "description": "Standard EICAR antivirus test string, not ransomware.",
                "tags": ["EICAR", "Security test"], "vt_detection": "Not queried"}
    if clean_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        return {"hash_type": "SHA256", "malware_family": "Empty file", "threat_score": 0,
                "verdict": "CLEAN", "description": "SHA-256 of a zero-byte file.", "tags": ["Empty file"], "vt_detection": "Not queried"}

    # Standard heuristic result for uncataloged hashes
    return {
        "hash_type": hash_type.upper(),
        "malware_family": "Unknown / Unclassified",
        "threat_actor": "None Correlated",
        "threat_type": "Unclassified File",
        "threat_score": 0,
        "verdict": "UNKNOWN",
        "vt_detection": "Not queried (external lookup required)",
        "first_seen": "N/A",
        "description": f"File signature ({hash_type.upper()}: {clean_hash}). Pivot to VirusTotal or AlienVault OTX for dynamic sandbox analysis.",
        "tags": ["File Hash", hash_type.upper()],
    }


# ============================================================
# MASTER INVESTIGATION CONTROLLER
# ============================================================

def investigate_ioc(raw_indicator: str, *, local_only=False, save_history=True) -> dict:
    """
    Execute full multi-source threat triage for an indicator.
    
    Returns a unified dossier dictionary containing:
      - Classification & normalized indicator
      - Network OSINT & GeoIP (for IPs and Domains)
      - CyberDash Local CTI detections (URLhaus, Feodo Tracker)
      - Correlated Threat Actors & MITRE TTPs
      - Calculated Threat Score (0-100) and SOC Verdict
      - Pivot URLs to external OSINT platforms
    """
    indicator = raw_indicator.strip()
    ioc_type = classify_ioc(indicator)

    dossier = {
        "indicator": indicator,
        "ioc_type": ioc_type,
        "verdict": "UNKNOWN",
        "threat_score": 0,
        "confidence": "Medium",
        "summary": "Indicator analyzed across threat feeds.",
        "threat_tags": [],
        "network": {},
        "feed_matches": [],
        "threat_actors": [],
        "pivots": {},
        "raw_details": {},
        "sources": {
            'local_indicators': {'status': 'not_queried'},
            'dns': {'status': 'not_queried'},
            'geoip': {'status': 'not_queried'},
            'hash_catalog': {'status': 'not_queried'},
            'external_reputation': {'status': 'not_queried', 'note': 'Pivot links are not provider queries.'},
        },
    }

    # ----------------------------------------------------------
    # 1. Type-Specific Enrichment
    # ----------------------------------------------------------
    if ioc_type in ("ipv4", "ipv6"):
        net_info = {} if local_only else enrich_ip(indicator)
        dossier["network"] = net_info
        dossier["pivots"] = {
            "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{indicator}",
            "AbuseIPDB": f"https://www.abuseipdb.com/check/{indicator}",
            "AlienVault OTX": f"https://otx.alienvault.com/indicator/ip/{indicator}",
            "Shodan": f"https://www.shodan.io/host/{indicator}",
            "Cisco Talos": f"https://talosintelligence.com/reputation_center/lookup?search={indicator}",
        }

    elif ioc_type == "domain":
        dom_info = {} if local_only else enrich_domain(indicator)
        dossier["network"] = dom_info.get("ip_enrichment") or {}
        dossier["raw_details"] = dom_info
        dossier["pivots"] = {
            "VirusTotal": f"https://www.virustotal.com/gui/domain/{indicator}",
            "AlienVault OTX": f"https://otx.alienvault.com/indicator/domain/{indicator}",
            "URLScan.io": f"https://urlscan.io/domain/{indicator}",
            "Cisco Talos": f"https://talosintelligence.com/reputation_center/lookup?search={indicator}",
        }

    elif ioc_type == "url":
        url_info = {} if local_only else enrich_url(indicator)
        dossier["network"] = url_info.get("domain_enrichment", {}).get("ip_enrichment") or {}
        dossier["raw_details"] = url_info
        dossier["pivots"] = {
            "VirusTotal": f"https://www.virustotal.com/gui/url/{indicator}",
            "URLhaus": f"https://urlhaus.abuse.ch/browse.php?search={indicator}",
            "URLScan.io": f"https://urlscan.io/",
        }

    elif ioc_type in ("md5", "sha1", "sha256"):
        hash_info = enrich_hash(indicator, ioc_type)
        dossier['sources']['hash_catalog']['status'] = 'available'
        dossier["raw_details"] = hash_info
        dossier["threat_score"] = hash_info.get("threat_score", 50)
        dossier["verdict"] = hash_info.get("verdict", "UNKNOWN")
        dossier["threat_tags"].extend(hash_info.get("tags", []))
        dossier["summary"] = hash_info.get("description", "")
        dossier["pivots"] = {
            "VirusTotal": f"https://www.virustotal.com/gui/file/{indicator}",
            "AlienVault OTX": f"https://otx.alienvault.com/indicator/file/{indicator}",
            "MalwareBazaar": f"https://bazaar.abuse.ch/sample/{indicator}/",
        }

    if not local_only and ioc_type in ('ipv4', 'ipv6', 'domain', 'url'):
        domain_data = dossier['raw_details'].get('domain_enrichment', dossier['raw_details'])
        dossier['sources']['dns']['status'] = domain_data.get('dns_status', dossier['network'].get('dns_status', 'unavailable'))
        dossier['sources']['geoip']['status'] = dossier['network'].get('geoip_status', 'not_queried')

    # ----------------------------------------------------------
    # 2. Local Database Threat Indicators Query
    # ----------------------------------------------------------
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            normalized = (str(ipaddress.ip_address(indicator)) if ioc_type in ("ipv4", "ipv6")
                          else indicator.lower().rstrip(".") if ioc_type in ("domain", "md5", "sha1", "sha256") else indicator)
            stored_type = "ip" if ioc_type in ("ipv4", "ipv6") else ioc_type
            cursor.execute("""SELECT * FROM threat_indicators
                WHERE indicator_type = ? AND indicator_value = ? LIMIT 10""", (stored_type, normalized))
            matches = cursor.fetchall()
            dossier['sources']['local_indicators']['status'] = 'available'
            for m in matches:
                dossier["feed_matches"].append(dict(m))
                dossier["threat_tags"].append(f"{m['source']} ({m['threat_type']})")
                dossier["threat_score"] = max(dossier["threat_score"], 85)
    except Exception:
        dossier['sources']['local_indicators']['status'] = 'unavailable'

    # ----------------------------------------------------------
    # 3. Threat Actor Correlation
    # ----------------------------------------------------------
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # Free-text substring matches are not evidence of IOC attribution.
            # Actor attribution requires structured, sourced IOC relationships.
            actors = []
            for a in actors:
                dossier["threat_actors"].append(dict(a))
                dossier["threat_tags"].append(f"APT: {a['name']}")
                dossier["threat_score"] = max(dossier["threat_score"], 90)
    except Exception as e:
        print(f"⚠️ Error correlating threat actors: {e}")

    # ----------------------------------------------------------
    # 4. Calculate Final Threat Score & SOC Verdict
    # ----------------------------------------------------------
    score = dossier["threat_score"]

    if dossier["feed_matches"]:
        score = max(score, 90)
    if dossier["threat_actors"]:
        score = max(score, 95)

    dossier["threat_score"] = min(100, max(0, score))

    if dossier["threat_score"] >= 80:
        dossier["verdict"] = "CRITICAL"
        dossier["confidence"] = "High"
    elif dossier["threat_score"] >= 60:
        dossier["verdict"] = "HIGH"
        dossier["confidence"] = "High"
    elif dossier["threat_score"] >= 30:
        dossier["verdict"] = "MEDIUM"
        dossier["confidence"] = "Medium"
    elif dossier["threat_score"] == 0 and dossier["verdict"] == "CLEAN":
        dossier["verdict"] = "CLEAN"
        dossier["confidence"] = "High"
    else:
        dossier["verdict"] = "UNKNOWN"
        dossier["confidence"] = "Low"

    # Deduplicate threat tags
    dossier["threat_tags"] = list(dict.fromkeys(dossier["threat_tags"]))

    # Save to investigation history
    geo_c = dossier.get("network", {}).get("country", "")
    if save_history:
        save_investigation_history(
            indicator=indicator,
            indicator_type=ioc_type,
            verdict=dossier["verdict"],
            threat_score=dossier["threat_score"],
            threat_tags=", ".join(dossier["threat_tags"]),
            geo_country=geo_c,
        )

    return dossier


# ============================================================
# INVESTIGATION HISTORY MANAGEMENT
# ============================================================

def save_investigation_history(indicator: str, indicator_type: str, verdict: str, threat_score: int, threat_tags: str, geo_country: str):
    """Save an investigation entry to SQLite history table."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO investigation_history
                (indicator, indicator_type, verdict, threat_score, threat_tags, geo_country)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (indicator, indicator_type, verdict, threat_score, threat_tags, geo_country))
            conn.commit()
    except Exception as e:
        print(f"⚠️ Error saving investigation history: {e}")


def get_recent_investigations(limit: int = 15) -> list:
    """Retrieve recent IOC investigations from the database."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM investigation_history
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def clear_investigation_history() -> bool:
    """Clear all past investigation logs (Admin action)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM investigation_history")
            conn.commit()
            return True
    except Exception:
        return False
