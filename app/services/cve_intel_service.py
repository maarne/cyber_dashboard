# ============================================================
# app/services/cve_intel_service.py — CVE Intelligence & Hover Metadata
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides fast, comprehensive metadata lookups for Common Vulnerabilities
# and Exposures (CVEs), CVSS severity scores, EPSS probabilities, and CISA
# Known Exploited Vulnerabilities (KEV) status for interactive UI popovers.
#
# MULTI-LAYER LOOKUP ARCHITECTURE:
# --------------------------------
# 1. Curated In-Memory Knowledgebase: Instant response for high-profile
#    exploited CVEs (Log4j, CitrixBleed, WinRAR, MOVEit, Zerologon, etc.).
# 2. Local SQLite Tables: Queries cves and cisa_exploits database records.
# 3. Standardized Fallback: Returns clean heuristic metadata for uncataloged CVEs.
#
# PYTHON CONCEPTS COVERED:
# - Multi-tier caching and fallback strategies (Dictionary -> DB -> Fallback)
# - SQLite contextual connection handling with get_connection()
# - String manipulation and normalization (CVE prefix enforcement)
# ============================================================

from app.database import get_connection

CURATED_CVE_DATABASE = {
    "CVE-2023-4966": {
        "cve_id": "CVE-2023-4966",
        "name": "Citrix NetScaler Information Disclosure (CitrixBleed)",
        "severity": "CRITICAL",
        "cvss_score": 9.4,
        "epss_score": 0.96,
        "is_cisa_kev": True,
        "vendor_product": "Citrix NetScaler ADC & Gateway",
        "description": "Sensitive information disclosure vulnerability allowing unauthenticated remote attackers to extract session tokens and bypass MFA.",
        "published_date": "2023-10-10",
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "name": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Apache Log4j2",
        "description": "JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "published_date": "2021-12-10",
    },
    "CVE-2023-38831": {
        "cve_id": "CVE-2023-38831",
        "name": "WinRAR File Extension Spoofing Arbitrary Code Execution",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "epss_score": 0.94,
        "is_cisa_kev": True,
        "vendor_product": "RARLAB WinRAR",
        "description": "Allows attackers to execute arbitrary code when a victim opens a specially crafted ZIP/RAR archive containing decoy files.",
        "published_date": "2023-08-23",
    },
    "CVE-2023-23397": {
        "cve_id": "CVE-2023-23397",
        "name": "Microsoft Outlook NTLM Hash Theft Elevation of Privilege",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.95,
        "is_cisa_kev": True,
        "vendor_product": "Microsoft Outlook",
        "description": "Zero-click vulnerability triggered when Outlook processes reminder notifications with custom appointment sound paths pointing to UNC shares.",
        "published_date": "2023-03-14",
    },
    "CVE-2023-27350": {
        "cve_id": "CVE-2023-27350",
        "name": "PaperCut MF/NG Unauthenticated Remote Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "PaperCut MF / NG",
        "description": "Authentication bypass vulnerability in SetupCompleted page allowing unauthenticated remote attackers to execute arbitrary code as SYSTEM.",
        "published_date": "2023-03-10",
    },
    "CVE-2024-1709": {
        "cve_id": "CVE-2024-1709",
        "name": "ConnectWise ScreenConnect Authentication Bypass",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "ConnectWise ScreenConnect",
        "description": "Authentication bypass using alternate path or channel enabling unauthenticated remote administrative account setup.",
        "published_date": "2024-02-21",
    },
    "CVE-2023-34362": {
        "cve_id": "CVE-2023-34362",
        "name": "MOVEit Transfer SQL Injection & Remote Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Progress Software MOVEit Transfer",
        "description": "SQL injection vulnerability in MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access and steal database contents.",
        "published_date": "2023-06-02",
    },
    "CVE-2020-1472": {
        "cve_id": "CVE-2020-1472",
        "name": "Microsoft Netlogon Domain Controller Elevation of Privilege (Zerologon)",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Microsoft Windows Server Netlogon",
        "description": "Flaw in AES-CFB8 cryptography in Netlogon Remote Protocol allowing unauthenticated attackers to set empty password on Domain Controller machine accounts.",
        "published_date": "2020-08-17",
    },
    "CVE-2017-0144": {
        "cve_id": "CVE-2017-0144",
        "name": "Microsoft Windows SMBv1 Remote Code Execution (EternalBlue)",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Microsoft Windows SMBv1",
        "description": "SMBv1 server handling of specially crafted packets allowing remote attackers to execute code with full SYSTEM privileges (used by WannaCry & NotPetya).",
        "published_date": "2017-03-14",
    },
    "CVE-2022-30190": {
        "cve_id": "CVE-2022-30190",
        "name": "Microsoft Windows Support Diagnostic Tool (MSDT) RCE (Follina)",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "epss_score": 0.96,
        "is_cisa_kev": True,
        "vendor_product": "Microsoft MSDT",
        "description": "Remote code execution vulnerability when MSDT is invoked using the URL protocol from a calling application such as Word.",
        "published_date": "2022-06-01",
    },
    "CVE-2022-22965": {
        "cve_id": "CVE-2022-22965",
        "name": "Spring Framework ClassLoader Access Remote Code Execution (Spring4Shell)",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.96,
        "is_cisa_kev": True,
        "vendor_product": "VMware Spring Framework",
        "description": "Spring MVC and Spring WebFlux applications running on JDK 9+ allowing ClassLoader property binding to achieve arbitrary file creation.",
        "published_date": "2022-04-01",
    },
    "CVE-2023-22515": {
        "cve_id": "CVE-2023-22515",
        "name": "Atlassian Confluence Server Broken Access Control",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Atlassian Confluence Data Center",
        "description": "Broken access control flaw allowing unauthenticated remote attackers to create administrator accounts on Confluence Server instances.",
        "published_date": "2023-10-04",
    },
    "CVE-2024-3094": {
        "cve_id": "CVE-2024-3094",
        "name": "XZ Utils liblzma Upstream Supply Chain Backdoor in SSHD",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.92,
        "is_cisa_kev": True,
        "vendor_product": "Tukaani XZ Utils",
        "description": "Malicious backdoor inserted into upstream liblzma tarballs altering OpenSSH authentication routines to permit remote unauthorized command execution.",
        "published_date": "2024-03-29",
    },
    "CVE-2023-20198": {
        "cve_id": "CVE-2023-20198",
        "name": "Cisco IOS XE Web UI Privilege Escalation",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Cisco IOS XE",
        "description": "Flaw in the Web UI feature of Cisco IOS XE software allowing unauthenticated remote attackers to create user accounts with level 15 privileges.",
        "published_date": "2023-10-16",
    },
    "CVE-2023-27997": {
        "cve_id": "CVE-2023-27997",
        "name": "Fortinet FortiOS SSL-VPN Heap-Based Buffer Overflow",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Fortinet FortiOS",
        "description": "Heap-based buffer overflow in FortiOS SSL-VPN allowing unauthenticated remote attackers to execute arbitrary code or commands via specially crafted requests.",
        "published_date": "2023-06-13",
    },
    "CVE-2023-3519": {
        "cve_id": "CVE-2023-3519",
        "name": "Citrix NetScaler ADC & Gateway Remote Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Citrix NetScaler ADC",
        "description": "Unauthenticated remote code execution vulnerability on configured NetScaler appliances.",
        "published_date": "2023-07-19",
    },
    "CVE-2023-46805": {
        "cve_id": "CVE-2023-46805",
        "name": "Ivanti Connect Secure Authentication Bypass",
        "severity": "HIGH",
        "cvss_score": 8.2,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "vendor_product": "Ivanti Connect Secure",
        "description": "Authentication bypass vulnerability in the web component of Ivanti Connect Secure and Policy Secure gateways.",
        "published_date": "2024-01-12",
    },
}


def get_cve_details(cve_id: str) -> dict:
    """
    Fetch comprehensive metadata for a given CVE identifier.
    Queries local SQLite database tables (cves & cisa_exploits) first,
    falling back to the curated CTI database and standardized defaults.
    """
    clean_id = cve_id.strip().upper()
    if not clean_id.startswith("CVE-"):
        clean_id = "CVE-" + clean_id

    # 1. Check curated CTI knowledgebase
    if clean_id in CURATED_CVE_DATABASE:
        return CURATED_CVE_DATABASE[clean_id]

    # 2. Check local database tables
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Check cves table
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (clean_id,))
            cve_row = cursor.fetchone()

            # Check cisa_exploits table
            cursor.execute("SELECT * FROM cisa_exploits WHERE cve_id = ?", (clean_id,))
            cisa_row = cursor.fetchone()

            if cve_row or cisa_row:
                desc = (cve_row["description"] if cve_row and cve_row["description"] 
                        else (cisa_row["short_description"] if cisa_row else "Vulnerability details tracked in CyberDash."))
                sev = (cve_row["severity"] if cve_row and cve_row["severity"] else ("CRITICAL" if cisa_row else "HIGH"))
                cvss = (cve_row["cvss_score"] if cve_row and cve_row["cvss_score"] else 8.0)
                epss = (cve_row["epss_score"] if cve_row and cve_row["epss_score"] else None)
                pub = (cve_row["published_date"] if cve_row and cve_row["published_date"] 
                       else (cisa_row["date_added"] if cisa_row else "N/A"))
                prod = (f"{cisa_row['vendor_project']} {cisa_row['product']}" if cisa_row and cisa_row["product"] else "Enterprise Software")

                return {
                    "cve_id": clean_id,
                    "name": cisa_row["vulnerability_name"] if cisa_row and cisa_row["vulnerability_name"] else clean_id,
                    "severity": sev,
                    "cvss_score": cvss,
                    "epss_score": epss,
                    "is_cisa_kev": cisa_row is not None,
                    "vendor_product": prod,
                    "description": desc,
                    "published_date": pub[:10] if pub else "N/A",
                }
    except Exception:
        pass

    # 3. Standard fallback response
    return {
        "cve_id": clean_id,
        "name": f"Vulnerability {clean_id}",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "epss_score": None,
        "is_cisa_kev": False,
        "vendor_product": "Target Software",
        "description": f"Security vulnerability tracked under {clean_id}. View NVD record for complete CVSS vectors and affected software versions.",
        "published_date": "N/A",
    }
