# ============================================================
# app/services/threat_actor_service.py — Threat Actor Intelligence Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides queries, search filtering, and comprehensive Cyber Threat
# Intelligence (CTI) profiles for Advanced Persistent Threats (APTs),
# state-sponsored units, and Ransomware-as-a-Service (RaaS) operations.
#
# WHAT IS AN "APT" (Advanced Persistent Threat)?
# ----------------------------------------------
# An APT is a sophisticated, sustained cyber attack campaign in which an
# intruder establishes an undetected presence in a network to harvest
# intelligence or conduct sabotage. APT groups are typically sponsored by
# nation-state intelligence agencies or well-funded cybercrime syndicates.
#
# PYTHON CONCEPTS COVERED:
# - Parameterized multi-field SQL search with SQL LIKE operator
# - Safe database cursor iteration and row-to-dictionary mapping
# - Data seeding with SQL INSERT OR IGNORE and unique constraints
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
            query += " AND (name LIKE ? OR aliases LIKE ? OR description LIKE ? OR associated_cves LIKE ? OR origin LIKE ? OR threat_type LIKE ? OR mitre_ttps LIKE ?)"
            pattern = f"%{search.strip()}%"
            params.extend([pattern, pattern, pattern, pattern, pattern, pattern, pattern])

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
    Seed comprehensive threat actor and ransomware group profiles.
    """
    initial_actors = [
        # --- RUSSIA ---
        {
            "name": "APT29 (Midnight Blizzard / Cozy Bear)",
            "aliases": "Cozy Bear, NOBELIUM, UNC2452, The Dukes, Dark Halo",
            "origin": "Russia (SVR)",
            "threat_type": "Nation-State Cyber Espionage",
            "target_sectors": "Government, Defense, IT & Cloud, Diplomacy, Think Tanks",
            "description": "APT29 is a premier Russian state-sponsored cyber espionage group attributed to Russia's Foreign Intelligence Service (SVR). Renowned for the SolarWinds supply chain attack, password spray campaigns against Microsoft executive mailboxes, and advanced cloud identity persistence.",
            "associated_cves": "CVE-2023-38831, CVE-2023-23397, CVE-2021-44228",
            "mitre_ttps": "T1190, T1078, T1566, T1059, T1098",
            "status": "Active / Critical Threat",
        },
        {
            "name": "APT28 (Fancy Bear / Forest Blizzard)",
            "aliases": "Fancy Bear, Strontium, Forest Blizzard, Pawn Storm, Sednit, Sofacy",
            "origin": "Russia (GRU 85th Main Special Service Center)",
            "threat_type": "Military Cyber Espionage & Information Operations",
            "target_sectors": "Defense, Government, NATO Alliances, Energy, Aviation, Media",
            "description": "APT28 is attributed to Russia's military intelligence agency (GRU unit 26165). Noted for high-profile political hack-and-leak operations, credential harvesting via Outlook NTLM leakage, and zero-day weaponization targeting NATO and Ukrainian military networks.",
            "associated_cves": "CVE-2023-23397, CVE-2022-30190, CVE-2017-8570",
            "mitre_ttps": "T1566, T1190, T1059, T1003, T1114",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Sandworm (APT44 / Seashell Blizzard)",
            "aliases": "Seashell Blizzard, TeleBots, Voodoo Bear, FROZENBARENTS",
            "origin": "Russia (GRU Unit 74455)",
            "threat_type": "Destructive Cyber Warfare & Critical Infrastructure Sabotage",
            "target_sectors": "Energy, Water Utilities, Telecommunications, Transportation, Government",
            "description": "Sandworm is an elite Russian military intelligence destructive unit responsible for the world's most damaging cyber attacks: Ukrainian power grid blackouts (BlackEnergy, Industroyer/CrashOverride), NotPetya global wiper worm, and AcidRain satellite modems wiper.",
            "associated_cves": "CVE-2017-0144, CVE-2022-30190, CVE-2023-38831",
            "mitre_ttps": "T1485, T1486, T1561, T1190, T1059",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Turla (Waterbug / Venomous Bear)",
            "aliases": "Waterbug, Venomous Bear, KRYPTON, Iron Hunter",
            "origin": "Russia (FSB Center 16)",
            "threat_type": "Advanced Nation-State Cyber Espionage",
            "target_sectors": "Government, Foreign Affairs, Defense, Research Institutes",
            "description": "Turla is a historic Russian FSB-linked cyber espionage operation tracking back over two decades. Specializes in complex stealth rootkits (Snake/Uroburos), satellite internet C2 hijacking, and sophisticated waterhole infections.",
            "associated_cves": "CVE-2023-38831, CVE-2021-40444",
            "mitre_ttps": "T1014, T1071, T1189, T1553, T1055",
            "status": "Active / High Threat",
        },

        # --- CHINA ---
        {
            "name": "Volt Typhoon (Vanguard Panda)",
            "aliases": "Vanguard Panda, BRONZE SILHOUETTE, Insidious Taurus",
            "origin": "China (MSS)",
            "threat_type": "Critical Infrastructure Pre-positioning & Sabotage",
            "target_sectors": "Telecommunications, Energy, Transportation, Water Utilities, Defense Base",
            "description": "Volt Typhoon is a state-sponsored Chinese cyber operation focused on long-term pre-positioning inside US and Allied critical infrastructure. Strictly avoids custom malware, relying almost exclusively on Living-off-the-Land (LotL) binaries, compromised edge routers, and valid credentials.",
            "associated_cves": "CVE-2023-27997, CVE-2023-3519, CVE-2023-46805",
            "mitre_ttps": "T1078, T1059, T1090, T1036, T1505",
            "status": "Active / Critical Threat",
        },
        {
            "name": "APT41 (Double Dragon / Wicked Panda)",
            "aliases": "Wicked Panda, Winnti, Barium, Brass Typhoon, Earth Baku",
            "origin": "China (MSS / Chengdu)",
            "threat_type": "Dual-Mission Cyber Espionage & Financial Crime",
            "target_sectors": "Technology, Gaming, Healthcare, Telecommunications, Supply Chain",
            "description": "APT41 is a prolific Chinese state contractor group unique for conducting state-sponsored espionage alongside financially motivated attacks. Prolific software supply chain attackers (ASUS, CCleaner) with deep zero-day stockpiles.",
            "associated_cves": "CVE-2021-44228, CVE-2019-19781, CVE-2020-10189",
            "mitre_ttps": "T1195, T1190, T1055, T1505, T1078",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Salt Typhoon (FamousSparrow / GhostEmperor)",
            "aliases": "FamousSparrow, GhostEmperor, Earth Estries",
            "origin": "China (MSS)",
            "threat_type": "Telecommunications & Wiretap Surveillance Espionage",
            "target_sectors": "Telecommunications, ISPs, Government, Hotels, Law Enforcement",
            "description": "Salt Typhoon is a Chinese state-sponsored adversary that breached major US and international telecommunications infrastructure to intercept lawfully authorized court wiretap systems, call records, and senior government communications.",
            "associated_cves": "CVE-2023-20198, CVE-2023-4966, CVE-2024-3400",
            "mitre_ttps": "T1190, T1078, T1040, T1005, T1090",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Mustang Panda (BRONZE PRESIDENT / RedDelta)",
            "aliases": "BRONZE PRESIDENT, RedDelta, Camaro Dragon, Earth Preta",
            "origin": "China (MSS)",
            "threat_type": "Regional Geopolitical Cyber Espionage",
            "target_sectors": "Government, Diplomatic Missions, NGOs, Catholic Church, Maritime",
            "description": "Mustang Panda focuses heavily on Southeast Asia, European Union diplomatic entities, and NGOs. Prolific users of USB worm malware, spear-phishing with malicious ZIP/LNK attachments, and custom PlugX/Hodur implants.",
            "associated_cves": "CVE-2023-38831, CVE-2017-11882",
            "mitre_ttps": "T1566, T1091, T1059, T1036, T1105",
            "status": "Active / High Threat",
        },
        {
            "name": "Flax Typhoon (Storm-0940)",
            "aliases": "Storm-0940, RedJuliett",
            "origin": "China",
            "threat_type": "IoT Botnet Infrastructure & Lateral Movement",
            "target_sectors": "Critical Infrastructure, Technology, Education, Government",
            "description": "Flax Typhoon built a massive botnet ('Raptor Train') comprising hundreds of thousands of compromised SOHO routers, IP cameras, and NVRs worldwide to route malicious espionage traffic and conduct reconnaissance across Taiwan and the US.",
            "associated_cves": "CVE-2023-28771, CVE-2021-36260, CVE-2020-8515",
            "mitre_ttps": "T1190, T1090, T1078, T1046, T1021",
            "status": "Active / High Threat",
        },

        # --- NORTH KOREA ---
        {
            "name": "Lazarus Group (APT38 / Hidden Cobra)",
            "aliases": "Hidden Cobra, Zinc, Labyrinth Chollima, Guardians of Peace",
            "origin": "North Korea (RGB)",
            "threat_type": "State-Sponsored Cybercrime, Heists & Espionage",
            "target_sectors": "Cryptocurrency, Financial Services, Defense, Technology, Aerospace",
            "description": "Lazarus Group is North Korea's primary cybercrime unit responsible for multi-billion-dollar cryptocurrency bridge exploits (Axie Infinity Ronin, Harmony Horizon, Coincheck) and ransomware operations to fund sanctioned national weapons programs.",
            "associated_cves": "CVE-2023-4863, CVE-2022-0609, CVE-2017-0144",
            "mitre_ttps": "T1566, T1204, T1059, T1486, T1547",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Kimsuky (Thallium / Velvet Chollima)",
            "aliases": "Thallium, Velvet Chollima, Black Banshee, Emerald Sleet",
            "origin": "North Korea (RGB 2nd Bureau)",
            "threat_type": "Foreign Policy Intelligence & Think Tank Espionage",
            "target_sectors": "Foreign Policy, Think Tanks, Nuclear Policy, Academic, Government",
            "description": "Kimsuky targets diplomats, defense experts, and foreign policy researchers worldwide. Masters of spear-phishing with spoofed journalist and academic personas, using multi-stage scripts and browser extension stealers (AFM, GoldDragon).",
            "associated_cves": "CVE-2020-0674, CVE-2018-8174",
            "mitre_ttps": "T1566, T1078, T1176, T1059, T1539",
            "status": "Active / High Threat",
        },
        {
            "name": "Andariel (APT45 / Stone Chollima)",
            "aliases": "Stone Chollima, Onyx Sleet, PLUTONIUM, Silent Chollima",
            "origin": "North Korea (RGB 5th Bureau)",
            "threat_type": "Defense Contractor Espionage & Healthcare Ransomware",
            "target_sectors": "Defense, Aerospace, Nuclear Energy, Healthcare, Manufacturing",
            "description": "Andariel focuses on stealing military blueprints, defense avionics, and naval engineering intelligence while operating ransomware campaigns (Maui ransomware) against US healthcare systems to generate immediate illicit revenue.",
            "associated_cves": "CVE-2021-44228, CVE-2023-38646",
            "mitre_ttps": "T1190, T1486, T1059, T1003, T1505",
            "status": "Active / High Threat",
        },

        # --- IRAN ---
        {
            "name": "Charming Kitten (APT35 / Mint Sandstorm)",
            "aliases": "Mint Sandstorm, Phosphorous, TA453, Yellow Garuda",
            "origin": "Iran (IRGC Intelligence Organization)",
            "threat_type": "Targeted Cyber Espionage & Social Engineering",
            "target_sectors": "Government, Defense, Think Tanks, Human Rights, Media, Nuclear Experts",
            "description": "Charming Kitten is an Iranian state-backed espionage group affiliated with the IRGC. Noted for elaborate multi-week conversational social engineering on WhatsApp and LinkedIn, credential harvesting portals, and deploying custom PowerShell backdoors (BellaCiao).",
            "associated_cves": "CVE-2021-44228, CVE-2021-34473, CVE-2022-26134",
            "mitre_ttps": "T1566, T1204, T1078, T1059, T1114",
            "status": "Active / Critical Threat",
        },
        {
            "name": "MuddyWater (Mango Sandstorm / Static Kitten)",
            "aliases": "Mango Sandstorm, Static Kitten, Mercury, Seedworm",
            "origin": "Iran (Ministry of Intelligence and Security - MOIS)",
            "threat_type": "Regional Telecommunications & Government Espionage",
            "target_sectors": "Telecommunications, Government, Energy, Defense, Transportation",
            "description": "MuddyWater operates on behalf of Iran's intelligence agency (MOIS). Specializes in abusing legitimate Remote Monitoring and Management (RMM) software (ScreenConnect, SimpleHelp, AnyDesk) and weaponized Office macros.",
            "associated_cves": "CVE-2024-1709, CVE-2020-1472, CVE-2017-11882",
            "mitre_ttps": "T1219, T1566, T1059, T1190, T1078",
            "status": "Active / High Threat",
        },
        {
            "name": "OilRig (APT34 / Hazel Sandstorm)",
            "aliases": "Hazel Sandstorm, EUROPIUM, Helix Kitten, Chrysene",
            "origin": "Iran (MOIS)",
            "threat_type": "Critical Infrastructure & Energy Cyber Espionage",
            "target_sectors": "Energy, Oil & Gas, Financial Services, Government, Telecommunications",
            "description": "OilRig is an Iranian cyber espionage cluster operating since at least 2014. Known for DNS tunneling protocols, side-loading custom WebShells (OutLookSync, Saitama), and targeting Middle Eastern critical infrastructure and financial hubs.",
            "associated_cves": "CVE-2017-0199, CVE-2018-8174, CVE-2021-40444",
            "mitre_ttps": "T1071, T1505, T1059, T1566, T1003",
            "status": "Active / High Threat",
        },

        # --- RANSOMWARE-AS-A-SERVICE (RaaS) & CYBERCRIME ---
        {
            "name": "LockBit 3.0",
            "aliases": "LockBit Black, Bitwise Spider",
            "origin": "International / RaaS Syndicate",
            "threat_type": "Ransomware-as-a-Service (RaaS)",
            "target_sectors": "Healthcare, Financial Services, Manufacturing, Critical Infrastructure, Education",
            "description": "LockBit is one of the most prolific Ransomware-as-a-Service (RaaS) operations in history. Operating on a double and triple-extortion model, they weaponize edge vulnerabilities (CitrixBleed, PaperCut, ScreenConnect) to deploy high-speed multi-threaded encryption payloads.",
            "associated_cves": "CVE-2023-4966, CVE-2023-27350, CVE-2024-1709",
            "mitre_ttps": "T1486, T1190, T1070, T1021, T1490",
            "status": "Active / High Threat",
        },
        {
            "name": "Cl0p Ransomware Gang",
            "aliases": "TA505, FIN11, Lace Tempest",
            "origin": "Cybercrime / Eastern Europe",
            "threat_type": "Mass Exploitation Ransomware & Data Extortion",
            "target_sectors": "Enterprise Technology, Financial, Education, Government, Healthcare",
            "description": "Cl0p is an aggressive cybercrime group famous for zero-day mass-exploitation of file transfer and enterprise platforms (MOVEit Transfer, GoAnywhere MFT, Accellion FTA, PaperCut). They exfiltrate petabytes of enterprise data for extortion without needing encryption.",
            "associated_cves": "CVE-2023-34362, CVE-2023-27350, CVE-2021-27101",
            "mitre_ttps": "T1190, T1567, T1486, T1059, T1530",
            "status": "Active / High Threat",
        },
        {
            "name": "BlackCat / ALPHV",
            "aliases": "ALPHV, BlackCat, NoName",
            "origin": "RaaS Syndicate",
            "threat_type": "Triple Extortion Ransomware",
            "target_sectors": "Healthcare, Legal, Defense, Retail, Technology, Logistics",
            "description": "ALPHV/BlackCat was a pioneer of Rust-based Ransomware-as-a-Service. Known for triple-extortion tactics (encryption, public leak site, DDoS) and the high-impact breach of Change Healthcare that disrupted US healthcare payment processing.",
            "associated_cves": "CVE-2023-22515, CVE-2021-44228, CVE-2024-1709",
            "mitre_ttps": "T1486, T1078, T1190, T1021, T1567",
            "status": "Active / High Threat",
        },
        {
            "name": "Black Basta",
            "aliases": "Storm-0257, Water Hydra",
            "origin": "Cybercrime / RaaS Syndicate",
            "threat_type": "High-Impact Enterprise Ransomware",
            "target_sectors": "Healthcare, Manufacturing, Critical Infrastructure, Defense, Construction",
            "description": "Black Basta emerged from former Conti leadership, rapidly carrying out double-extortion attacks against critical infrastructure and health systems (Ascension Health). Known for initial access through Qakbot, DarkGate, and massive Teams spamming social engineering.",
            "associated_cves": "CVE-2024-1709, CVE-2024-21887, CVE-2023-38831",
            "mitre_ttps": "T1486, T1566, T1059, T1021, T1490",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Scattered Spider (UNC3944 / Octo Tempest)",
            "aliases": "UNC3944, Starfraud, Octo Tempest, Muddled Libra",
            "origin": "International Cybercrime Syndicate",
            "threat_type": "Social Engineering, Identity Theft & RaaS Affiliate",
            "target_sectors": "Hospitality, Retail, Telecommunications, Financial Services, SaaS Providers",
            "description": "Scattered Spider is a young, agile cybercrime syndicate notorious for deep social engineering: Voice Phishing (vishing) IT helpdesks, SIM swapping, and MFA fatigue. Notable for the crippling 2023 MGM Resorts and Caesars Entertainment breaches.",
            "associated_cves": "CVE-2023-34048, CVE-2021-44228",
            "mitre_ttps": "T1566, T1621, T1078, T1556, T1098",
            "status": "Active / Critical Threat",
        },
        {
            "name": "Akira Ransomware",
            "aliases": "Punk Spider, Storm-1567",
            "origin": "RaaS Syndicate",
            "threat_type": "Multi-Platform Double Extortion Ransomware",
            "target_sectors": "Education, Finance, Manufacturing, Healthcare, Real Estate",
            "description": "Akira targets both Windows and Linux VMware ESXi hypervisors. Gained notoriety for rapidly exploiting unpatched Cisco ASA/FTD SSL-VPNs without MFA and SonicWall firewalls for initial perimeter compromise.",
            "associated_cves": "CVE-2023-20269, CVE-2024-40766, CVE-2023-27532",
            "mitre_ttps": "T1190, T1078, T1486, T1021, T1490",
            "status": "Active / High Threat",
        },
        {
            "name": "Play Ransomware (PlayCrypt)",
            "aliases": "PlayCrypt, Balloonfly",
            "origin": "Cybercrime Syndicate",
            "threat_type": "Double Extortion Ransomware",
            "target_sectors": "Local Government, Aviation, Healthcare, Automotive, Managed Service Providers",
            "description": "Play Ransomware uses closed-door bespoke tooling with no public affiliate program. Gained fame for inventing the OWASSRF exploit chain combining CVE-2022-41080 and CVE-2022-41082 to bypass Microsoft Exchange URL rewrites.",
            "associated_cves": "CVE-2022-41080, CVE-2022-41082, CVE-2023-3519",
            "mitre_ttps": "T1190, T1486, T1059, T1003, T1021",
            "status": "Active / High Threat",
        },
        {
            "name": "Rhysida Ransomware",
            "aliases": "Vice Society Affiliates",
            "origin": "Cybercrime / RaaS",
            "threat_type": "Opportunistic Double Extortion Ransomware",
            "target_sectors": "Education, Healthcare, Government, Cultural Institutions, Mining",
            "description": "Rhysida positions itself as a 'cybersecurity team' auditing victims. Famous for devastating breaches of the British Library, Prospect Medical Holdings, and Insomniac Games, aggressively auctioning stolen data on dark web portals.",
            "associated_cves": "CVE-2020-1472, CVE-2023-27532",
            "mitre_ttps": "T1486, T1566, T1078, T1059, T1567",
            "status": "Active / High Threat",
        },
        {
            "name": "BianLian",
            "aliases": "RedCurl Affiliates",
            "origin": "Cybercrime Syndicate",
            "threat_type": "Data Exfiltration & Pure Extortion",
            "target_sectors": "Healthcare, Professional Services, Banking, Manufacturing",
            "description": "Originally a high-speed Go-based ransomware group, BianLian pivoted entirely to pure data theft and extortion after a decryptor was released. They extort organizations exclusively by threatening public disclosure of sensitive records and regulatory reporting.",
            "associated_cves": "CVE-2023-3519, CVE-2021-44228",
            "mitre_ttps": "T1567, T1190, T1078, T1005, T1059",
            "status": "Active / High Threat",
        },
        {
            "name": "Medusa Ransomware",
            "aliases": "MedusaLocker Affiliates",
            "origin": "RaaS Syndicate",
            "threat_type": "Double Extortion Ransomware & Media Leaks",
            "target_sectors": "K-12 Education, Healthcare, Non-Profit, Manufacturing, Public Utilities",
            "description": "Medusa operates a prominent dark web leak site ('Medusa Blog') with live countdown timers and Telegram broadcast channels. They utilize living-off-the-land tools, batch scripts, and PowerShell to disable Windows Defender before encryption.",
            "associated_cves": "CVE-2023-27350, CVE-2023-4966",
            "mitre_ttps": "T1486, T1562, T1059, T1021, T1490",
            "status": "Active / High Threat",
        },
        {
            "name": "FIN7 (Carbanak / Sangria Tempest)",
            "aliases": "Carbanak, Sangria Tempest, ELBRUS, Navigator Group",
            "origin": "Organized Cybercrime / Eastern Europe",
            "threat_type": "Corporate Extortion, POS Malware & Ransomware Enablement",
            "target_sectors": "Retail, Restaurant, Hospitality, Financial, Technology",
            "description": "FIN7 is one of the most organized cybercrime corporations in history, once operating fake front cybersecurity companies (Bastion Secure) to recruit unwitting penetration testers. Historically stole over a billion dollars in credit cards via Carbanak POS malware.",
            "associated_cves": "CVE-2023-34362, CVE-2021-44228",
            "mitre_ttps": "T1566, T1059, T1055, T1505, T1078",
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
            # Also update existing rows with richer details if needed
            cursor.execute("""
                UPDATE threat_actors
                SET aliases = ?,
                    origin = ?,
                    threat_type = ?,
                    target_sectors = ?,
                    description = ?,
                    associated_cves = ?,
                    mitre_ttps = ?,
                    status = ?
                WHERE name = ?
            """, (
                actor["aliases"],
                actor["origin"],
                actor["threat_type"],
                actor["target_sectors"],
                actor["description"],
                actor["associated_cves"],
                actor["mitre_ttps"],
                actor["status"],
                actor["name"],
            ))
        conn.commit()
