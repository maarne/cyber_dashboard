# ============================================================
# app/services/threat_actor_service.py — Threat Actor Intelligence Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides queries and initial intelligence seeding for Threat Actors,
# APT Groups, and Ransomware-as-a-Service (RaaS) syndicates.
# Data is modeled after MITRE ATT&CK® Enterprise CTI and CISA Advisories.
# ============================================================

from app.database import get_connection


def get_all_threat_actors(search: str = None, sector: str = None):
    """
    Fetch all threat actor profiles from the database with optional search
    and target sector filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM threat_actors WHERE 1=1"
        params = []

        if search:
            query += " AND (name LIKE ? OR aliases LIKE ? OR description LIKE ? OR associated_cves LIKE ?)"
            pattern = f"%{search.strip()}%"
            params.extend([pattern, pattern, pattern, pattern])

        if sector:
            query += " AND target_sectors LIKE ?"
            params.append(f"%{sector.strip()}%")

        query += " ORDER BY name ASC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_threat_actor_by_id(actor_id: int):
    """
    Fetch a single threat actor profile by its ID.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_actors WHERE id = ?", (actor_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def seed_default_threat_actors():
    """
    Seed initial threat actor profiles if the table is empty.
    """
    initial_actors = [
        {
            "name": "APT29 (Midnight Blizzard / Cozy Bear)",
            "aliases": "Cozy Bear, NOBELIUM, UNC2452, The Dukes",
            "origin": "Russia (SVR)",
            "threat_type": "Nation-State Cyber Espionage",
            "target_sectors": "Government, Defense, IT & Cloud, Diplomacy, Think Tanks",
            "description": "APT29 is a highly sophisticated Russian state-sponsored cyber espionage group attributed to Russia's Foreign Intelligence Service (SVR). Known for SolarWinds supply chain attacks, Microsoft Cloud tenant compromises, and advanced persistence.",
            "associated_cves": "CVE-2023-38831, CVE-2023-23397, CVE-2021-44228",
            "mitre_ttps": "T1190, T1078, T1566, T1059, T1098",
            "status": "Active / Critical Threat",
        },
        {
            "name": "LockBit 3.0",
            "aliases": "LockBit Black, Bitwise Spider",
            "origin": "International / RaaS",
            "threat_type": "Ransomware-as-a-Service (RaaS)",
            "target_sectors": "Healthcare, Financial Services, Manufacturing, Critical Infrastructure, Education",
            "description": "LockBit is one of the most active Ransomware-as-a-Service (RaaS) operations globally. Operating on a double and triple-extortion model, they exploit edge vulnerabilities (CitrixBleed, PaperCut) to deploy custom high-speed encryption payloads.",
            "associated_cves": "CVE-2023-4966, CVE-2023-27350, CVE-2021-34527",
            "mitre_ttps": "T1486, T1190, T1070, T1021, T1490",
            "status": "Active / High Threat",
        },
        {
            "name": "Lazarus Group (APT38 / Hidden Cobra)",
            "aliases": "Hidden Cobra, Zinc, Labyrinth Chollima, Guardians of Peace",
            "origin": "North Korea (RGB)",
            "threat_type": "State-Sponsored Cybercrime & Espionage",
            "target_sectors": "Cryptocurrency, Financial Services, Defense, Technology, Aerospace",
            "description": "Lazarus Group is a North Korean state-sponsored threat group notorious for high-profile financial heists, cryptocurrency bridge exploits (Ronin, Harmony), and WannaCry ransomware. Known for Trojanized open-source software and social engineering via LinkedIn.",
            "associated_cves": "CVE-2023-4863, CVE-2022-0609, CVE-2017-0144",
            "mitre_ttps": "T1566, T1204, T1059, T1486, T1547",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Volt Typhoon (Vanguard Panda)",
            "aliases": "Vanguard Panda, BRONZE SILHOUETTE",
            "origin": "China (MSS)",
            "threat_type": "Nation-State Critical Infrastructure Pre-positioning",
            "target_sectors": "Telecommunications, Energy, Transportation, Water Utilities, Defense Base",
            "description": "Volt Typhoon is a Chinese state-sponsored actor focused on pre-positioning and persistence within US critical infrastructure networks. Employs 'Living off the Land' (LotL) techniques, compromised SOHO routers, and stolen valid credentials to avoid signature detection.",
            "associated_cves": "CVE-2023-27997, CVE-2023-3519, CVE-2023-46805",
            "mitre_ttps": "T1078, T1059, T1090, T1036, T1505",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Cl0p Ransomware Gang",
            "aliases": "TA505, FIN11, Lace Tempest",
            "origin": "Cybercrime / Eastern Europe",
            "threat_type": "Mass Exploitation Ransomware & Data Extortion",
            "target_sectors": "Enterprise Technology, Financial, Education, Government, Healthcare",
            "description": "Cl0p is an aggressive cybercrime group famous for zero-day mass-exploitation of file transfer and enterprise platforms (MOVEit Transfer, GoAnywhere MFT, Accellion FTA). They exfiltrate massive data volumes for extortion without relying strictly on encryption.",
            "associated_cves": "CVE-2023-34362, CVE-2023-27350, CVE-2021-27101",
            "mitre_ttps": "T1190, T1567, T1486, T1059, T1530",
            "status": "Active / High Threat",
        },
        {
            "name": "Scattered Spider (UNC3944)",
            "aliases": "UNC3944, Starfraud, Octo Tempest",
            "origin": "International Cybercrime Syndicate",
            "threat_type": "Social Engineering & RaaS Affiliate",
            "target_sectors": "Hospitality, Retail, Telecommunications, Financial Services, SaaS Providers",
            "description": "Scattered Spider is a highly agile threat group specializing in sophisticated Vishing (voice phishing), SIM swapping, and MFA fatigue attacks targeting helpdesks. Frequently partners with ALPHV/BlackCat to deploy ransomware.",
            "associated_cves": "CVE-2023-34048, CVE-2021-44228",
            "mitre_ttps": "T1566, T1621, T1078, T1556, T1098",
            "status": "Active / High Threat",
        },
        {
            "name": "APT28 (Fancy Bear / Strontium)",
            "aliases": "Fancy Bear, Strontium, Forest Blizzard, Pawn Storm",
            "origin": "Russia (GRU 85th Main Special Service Center)",
            "threat_type": "Military Cyber Espionage & Information Operations",
            "target_sectors": "Defense, Government, NATO Alliances, Energy, Aviation, Media",
            "description": "APT28 is attributed to Russia's military intelligence agency (GRU). Noted for high-profile political hack-and-leak operations, credential harvesting via Outlook vulnerabilities, and targeting NATO defense entities.",
            "associated_cves": "CVE-2023-23397, CVE-2022-30190, CVE-2017-8570",
            "mitre_ttps": "T1566, T1190, T1059, T1003, T1114",
            "status": "Active / Critical Threat",
        },
        {
            "name": "BlackCat / ALPHV",
            "aliases": "ALPHV, BlackCat, NoName",
            "origin": "RaaS Syndicate",
            "threat_type": "Triple Extortion Ransomware",
            "target_sectors": "Healthcare, Legal, Defense, Retail, Technology, Logistics",
            "description": "ALPHV/BlackCat is a sophisticated Rust-based Ransomware-as-a-Service operation. Known for triple-extortion tactics (encryption, data leak, DDoS) and targeting major healthcare and enterprise networks.",
            "associated_cves": "CVE-2023-22515, CVE-2021-44228",
            "mitre_ttps": "T1486, T1078, T1190, T1021, T1567",
            "status": "Active / High Threat",
        },
    ]

    with get_connection() as conn:
        cursor = conn.cursor()
        for actor in initial_actors:
            cursor.execute("""
                INSERT OR IGNORE INTO threat_actors
                (name, aliases, origin, threat_type, target_sectors, description, associated_cves, mitre_ttps, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                actor["name"],
                actor["aliases"],
                actor["origin"],
                actor["threat_type"],
                actor["target_sectors"],
                actor["description"],
                actor["associated_cves"],
                actor["mitre_ttps"],
                actor["status"],
            ))
        conn.commit()
