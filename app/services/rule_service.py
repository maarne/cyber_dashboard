# ============================================================
# app/services/rule_service.py — Detection Rule Repository Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides CRUD functions and seed intelligence for Sigma (SIEM)
# and YARA (Malware) Detection Rules mapped to MITRE ATT&CK® TTPs,
# complete with step-by-step SIEM and EDR product deployment guides.
#
# WHAT ARE SIGMA AND YARA RULES?
# ------------------------------
# 1. Sigma: A generic, open signature format for SIEM systems (like
#    Splunk, Microsoft Sentinel, Elastic EQL, QRadar). It describes log
#    events in YAML format, allowing analysts to write detection rules
#    once and convert them to any target SIEM query language.
# 2. YARA: The pattern matching swiss-knife for malware researchers.
#    YARA rules identify malware samples based on textual or binary
#    patterns (strings, regex, byte sequences) in files or memory.
#
# PYTHON CONCEPTS COVERED:
# - Dynamic SQL query building with WHERE 1=1 and parameter lists
# - Safe database transactions (INSERT, UPDATE, DELETE) with SQLite
# - Deduplication queries with SQL MIN(id) and subqueries
# ============================================================

from app.database import get_connection


def get_all_detection_rules(rule_type: str = None, search: str = None, siem: str = None):
    """
    Fetch all detection rules from the database with optional filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM detection_rules WHERE 1=1"
        params = []

        if rule_type and rule_type.upper() != 'ALL':
            query += " AND UPPER(rule_type) = ?"
            params.append(rule_type.upper())

        if siem and siem.upper() != 'ALL':
            query += " AND (UPPER(target_siem) LIKE ? OR UPPER(target_siem) = 'GENERIC')"
            params.append(f"%{siem.upper()}%")

        if search:
            pattern = f"%{search.strip()}%"
            query += " AND (title LIKE ? OR mitre_ttp LIKE ? OR target_cve LIKE ? OR description LIKE ? OR code_content LIKE ? OR deployment_guide LIKE ?)"
            params.extend([pattern, pattern, pattern, pattern, pattern, pattern])

        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for row in rows:
            r = dict(row)
            if not r.get("deployment_guide"):
                r["deployment_guide"] = ""
            result.append(r)
        return result


def get_rule_by_id(rule_id: int):
    """
    Fetch a single detection rule by ID.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM detection_rules WHERE id = ?", (rule_id,))
        row = cursor.fetchone()
        if row:
            r = dict(row)
            if not r.get("deployment_guide"):
                r["deployment_guide"] = ""
            return r
        return None


def save_detection_rule(data: dict):
    """
    Create a new detection rule.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO detection_rules
            (title, rule_type, mitre_ttp, severity, target_cve, description, code_content, target_siem, deployment_guide)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(data.get("title") or "").strip(),
            str(data.get("rule_type") or "Sigma").strip(),
            str(data.get("mitre_ttp") or "").strip(),
            str(data.get("severity") or "HIGH").upper().strip(),
            str(data.get("target_cve") or "").strip(),
            str(data.get("description") or "").strip(),
            str(data.get("code_content") or "").strip(),
            str(data.get("target_siem") or "Generic").strip(),
            str(data.get("deployment_guide") or "").strip(),
        ))
        conn.commit()
        return cursor.lastrowid


def update_detection_rule(rule_id: int, data: dict):
    """
    Update an existing detection rule.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE detection_rules
            SET title = ?,
                rule_type = ?,
                mitre_ttp = ?,
                severity = ?,
                target_cve = ?,
                description = ?,
                code_content = ?,
                target_siem = ?,
                deployment_guide = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            str(data.get("title") or "").strip(),
            str(data.get("rule_type") or "Sigma").strip(),
            str(data.get("mitre_ttp") or "").strip(),
            str(data.get("severity") or "HIGH").upper().strip(),
            str(data.get("target_cve") or "").strip(),
            str(data.get("description") or "").strip(),
            str(data.get("code_content") or "").strip(),
            str(data.get("target_siem") or "Generic").strip(),
            str(data.get("deployment_guide") or "").strip(),
            rule_id,
        ))
        conn.commit()
        return cursor.rowcount > 0


def delete_detection_rule(rule_id: int):
    """
    Delete a detection rule by ID.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM detection_rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cursor.rowcount > 0


def seed_default_detection_rules():
    """
    Seed 15 production-grade Sigma & YARA detection rules with detailed SIEM/EDR deployment guides.
    """
    rules = [
        {
            "title": "Log4j JNDI Remote Code Execution (CVE-2021-44228)",
            "rule_type": "Sigma",
            "mitre_ttp": "T1190 - Exploit Public-Facing Application",
            "severity": "CRITICAL",
            "target_cve": "CVE-2021-44228",
            "target_siem": "Splunk / Sentinel / Elastic",
            "description": "Detects JNDI lookup payloads in HTTP User-Agent, URI, or headers characteristic of Apache Log4j RCE exploitation.",
            "code_content": """title: Apache Log4j JNDI RCE Exploitation Attempt
id: 5f1b29a2-9b24-4f24-9b25-log4j2cve
status: production
description: Detects JNDI lookup strings in web server requests targeting CVE-2021-44228.
author: CyberDash SecOps
logsource:
    category: webserver
detection:
    jndi_pattern:
        cs-method:
            - 'GET'
            - 'POST'
        c-uri|contains:
            - '${jndi:ldap:'
            - '${jndi:rmi:'
            - '${jndi:dns:'
            - '${jndi:nis:'
            - '${jndi:nds:'
            - '${jndi:corba:'
    condition: jndi_pattern
falsepositives:
    - Security scanner vulnerability auditing
level: critical""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (SPL Query):
1. Navigate to **Search & Reporting** in Splunk.
2. Run the following SPL query against web access logs (`index=web OR index=proxy`):
```spl
(index=web OR index=proxy) (cs_method="GET" OR cs_method="POST") 
(uri="*${jndi:ldap:*" OR uri="*${jndi:rmi:*" OR uri="*${jndi:dns:*" OR user_agent="*${jndi:*")
| table _time, src_ip, dest_ip, cs_method, uri, user_agent
```
3. Click **Save As** -> **Alert**. Set Triggering to *Per Result* and actions to send PagerDuty / Webhook alert.

#### 🔵 Microsoft Sentinel (KQL Query):
1. Go to **Microsoft Sentinel** -> **Logs**.
2. Run KQL query:
```kql
W3CIISLog
| where csMethod in ("GET", "POST")
| where csUriQuery has_any ("${jndi:ldap:", "${jndi:rmi:", "${jndi:dns:", "${jndi:nis:")
   or UserAgent has "${jndi:"
| project TimeGenerated, cIP, sIP, csMethod, csUriStem, csUriQuery, UserAgent
```
3. Create an Analytics Rule set to run every 5 minutes with a lookup window of 5 minutes.

#### 🟢 Elastic (EQL Query):
```eql
sequence by host.name
  [http where http.request.method in ("GET", "POST") and 
   http.request.body.content contains "${jndi:" or http.request.referrer contains "${jndi:"]
```"""
        },
        {
            "title": "LockBit 3.0 Ransomware Binary Payload Signature",
            "rule_type": "YARA",
            "mitre_ttp": "T1486 - Data Encrypted for Impact",
            "severity": "CRITICAL",
            "target_cve": "N/A",
            "target_siem": "YARA / Endpoint AV / EDR",
            "description": "YARA rule matching LockBit 3.0 (Black) executable headers, shadow copy deletion commands, and ransom note strings.",
            "code_content": """rule LockBit_3_Ransomware {
    meta:
        description = "Detects LockBit 3.0 (LockBit Black) ransomware binaries"
        author = "CyberDash Threat Intel"
        date = "2026-08-13"
        reference = "https://attack.mitre.org/software/S1071/"
        severity = "CRITICAL"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide
        $s2 = "bcdedit /set {default} recoveryenabled No" ascii wide
        $s3 = "LockBit 3.0 the world's most trustworthy ransomware" ascii wide
        $hex_pattern = { 8B 45 ?? 83 E8 04 89 45 ?? 8B 4D ?? 8B 55 ?? 33 02 89 01 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $hex_pattern)
}""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🛡️ YARA CLI Scanning (Linux / Windows):
1. Save this rule to a file named `lockbit3.yar`.
2. Scan suspect directories or process memory:
```bash
# Scan a specific directory recursively:
yara -r lockbit3.yar /path/to/suspect/directory

# Scan active running process memory by PID:
yara64.exe -m lockbit3.yar <PID>
```

#### 💻 Velociraptor / CrowdStrike / EDR Deployment:
1. In **Velociraptor**, create a VQL Artifact utilizing `Generic.Detection.Yara`.
2. Upload `lockbit3.yar` into the artifact definition and deploy a sweep job across endpoints.
3. In **Defender for Endpoint**, add the YARA hash indicators into Custom Detection Rules under Threat Analytics."""
        },
        {
            "title": "CitrixBleed Session Token Information Disclosure (CVE-2023-4966)",
            "rule_type": "Sigma",
            "mitre_ttp": "T1190 - Exploit Public-Facing Application",
            "severity": "HIGH",
            "target_cve": "CVE-2023-4966",
            "target_siem": "Splunk / Elastic",
            "description": "Detects overlong GET requests to NetScaler OAuth endpoints targeting CitrixBleed session cookie leakage.",
            "code_content": """title: CitrixBleed NetScaler Session Leakage
id: c4f23e01-9a71-4b12-9c12-citrixbleed
status: production
description: Detects exploited NetScaler endpoints returning session tokens.
logsource:
    category: webserver
    product: netscaler
detection:
    selection:
        cs-method: 'GET'
        c-uri|contains: '/oauth/idp/logout'
        cs-header|contains: 'Host:'
    condition: selection
level: high""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (SPL Query):
```spl
sourcetype="citrix:netscaler:web" cs_method="GET" uri_path="*/oauth/idp/logout*"
| stats count by src_ip, uri_path, user_agent
| where count > 10
```

#### 🔵 Microsoft Sentinel (KQL Query):
```kql
CommonSecurityLog
| where DeviceVendor == "Citrix" and DeviceProduct == "NetScaler"
| where RequestURL has "/oauth/idp/logout"
| summarize RequestCount = count() by SourceIP, RequestURL
```"""
        },
        {
            "title": "Cobalt Strike Beacon In-Memory DLL Injection",
            "rule_type": "YARA",
            "mitre_ttp": "T1055 - Process Injection",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "YARA / Memory Scanner",
            "description": "Detects Cobalt Strike Beacon reflective loader and memory configuration artifacts in active process memory.",
            "code_content": """rule CobaltStrike_Beacon_Memory {
    meta:
        description = "Detects Cobalt Strike Beacon in process memory"
        author = "CyberDash CTI"
        threat_level = 4
    strings:
        $beacon_config = { 2e 2f 2e 2f 2e 2c 00 00 00 01 00 00 00 02 }
        $ref_loader = { 4D 5A 41 52 55 48 89 E5 48 83 EC 20 48 8D 05 }
        $cmd_pipe = "\\\\.\\pipe\\MSSE-" ascii
    condition:
        any of ($beacon_config, $ref_loader, $cmd_pipe)
}""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🧠 Memory Dump Scanning with Volatility 3:
1. Extract memory dump via WinPmem or DumpIt.
2. Run Volatility YARA scan plugin:
```bash
vol.py -f memory.raw windows.vaddump.VadDump --yara-file cobaltstrike.yar
```"""
        },
        {
            "title": "Suspicious Encoded Base64 PowerShell Execution",
            "rule_type": "Sigma",
            "mitre_ttp": "T1059.001 - PowerShell",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "Splunk / Sentinel / QRadar",
            "description": "Detects execution of PowerShell with hidden window and encoded command flags commonly used in initial access loaders.",
            "code_content": """title: Suspicious Encoded PowerShell Command Execution
id: 3c9b708d-e6b7-4a55-8712-encodedps
status: production
description: Detects obfuscated Base64 command arguments passed to powershell.exe.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - ' -e '
            - ' -enc '
            - ' -encodedcommand '
            - ' -w hidden '
            - ' -nop '
    condition: selection
level: high""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (SPL Query):
```spl
index=windows EventCode=4688 OR EventCode=1 (process="*powershell.exe" OR process="*pwsh.exe")
(CommandLine="*-e *" OR CommandLine="*-enc *" OR CommandLine="*-encodedcommand *" OR CommandLine="*-w hidden*")
| table _time, host, User, CommandLine, ParentCommandLine
```

#### 🔵 Microsoft Sentinel (KQL Query):
```kql
SecurityEvent
| where EventID == 4688
| where ProcessName endswith "powershell.exe" or ProcessName endswith "pwsh.exe"
| where CommandLine has_any ("-enc", "-e", "-encodedcommand", "-w hidden", "-nop")
| project TimeGenerated, Computer, Account, ProcessName, CommandLine
```"""
        },
        {
            "title": "Mimikatz LSASS Password Memory Dumping",
            "rule_type": "Sigma",
            "mitre_ttp": "T1003.001 - LSASS Memory",
            "severity": "CRITICAL",
            "target_cve": "N/A",
            "target_siem": "Splunk / Sentinel / Sysmon",
            "description": "Detects process access requests with generic read/all access permissions to lsass.exe process memory (Sysmon Event 10).",
            "code_content": """title: LSASS Process Memory Access by Non-System Process
id: a29103e2-9b21-4f91-9123-lsassdump
status: production
description: Detects potential credential harvesting targeting LSASS process memory.
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess:
            - '0x1410'
            - '0x1010'
            - '0x1f0fff'
    filter:
        SourceImage|endswith:
            - '\\svchost.exe'
            - '\\msmpeng.exe'
    condition: selection and not filter
level: critical""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (Sysmon Event Code 10):
```spl
index=windows EventCode=10 TargetImage="*\\lsass.exe"
(GrantedAccess="0x1410" OR GrantedAccess="0x1010" OR GrantedAccess="0x1f0fff")
NOT SourceImage="*\\Windows Defender\\*" NOT SourceImage="*\\svchost.exe"
| table _time, host, SourceImage, GrantedAccess, SourceUser
```"""
        },
        {
            "title": "Zerologon Netlogon Privilege Escalation (CVE-2020-1472)",
            "rule_type": "Sigma",
            "mitre_ttp": "T1068 - Exploitation for Privilege Escalation",
            "severity": "CRITICAL",
            "target_cve": "CVE-2020-1472",
            "target_siem": "Splunk / Sentinel",
            "description": "Detects automated computer password resets targeting Domain Controllers via unauthenticated Netlogon RPC (Event Code 4742).",
            "code_content": """title: Zerologon Domain Controller Password Reset
id: b29402e1-7c91-4e12-8123-zerologon
status: production
description: Detects computer account password changes with empty passwords characteristic of Zerologon.
logsource:
    category: identity
    product: windows
detection:
    selection:
        EventID: 4742
        PasswordLastSet: '*'
        TargetUserName|endswith: '$'
    condition: selection
level: critical""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🔵 Microsoft Sentinel (KQL Query):
```kql
SecurityEvent
| where EventID in (4742, 5829)
| where TargetUserName endswith "$"
| project TimeGenerated, Computer, TargetUserName, Activity
```"""
        },
        {
            "title": "MOVEit Transfer SQLi & File Exfiltration (CVE-2023-34362)",
            "rule_type": "Sigma",
            "mitre_ttp": "T1190 - Exploit Public-Facing Application",
            "severity": "CRITICAL",
            "target_cve": "CVE-2023-34362",
            "target_siem": "Splunk / Elastic / Sentinel",
            "description": "Detects web requests to MOVEit guestaccess.aspx and human.aspx endpoint invoking unauthorized file downloads.",
            "code_content": """title: MOVEit Transfer Web Exploitation Attempt
id: m38101a2-8c12-4f90-8812-moveit
status: production
description: Detects SQLi payload parameters passed to MOVEit Transfer IIS endpoints.
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains:
            - '/guestaccess.aspx'
            - '/human.aspx'
        c-uri-query|contains:
            - 'X-MOVEit-Transaction'
            - 'human2.aspx'
    condition: selection
level: critical""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (W3C IIS Logs):
```spl
sourcetype="iis" (cs_uri_stem="*/guestaccess.aspx" OR cs_uri_stem="*/human.aspx")
| stats count by c_ip, cs_uri_stem, cs_method
```"""
        },
        {
            "title": "RedLine Stealer Credential Harvesting Signature",
            "rule_type": "YARA",
            "mitre_ttp": "T1555 - Credentials from Password Stores",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "YARA / Endpoint AV",
            "description": "YARA rule detecting RedLine Stealer .NET assembly strings and browser credential vault theft routines.",
            "code_content": """rule RedLine_Stealer_Payload {
    meta:
        description = "Detects RedLine Infostealer .NET binaries"
        author = "CyberDash Threat Intel"
    strings:
        $s1 = "Select * from Win32_ComputerSystem" wide
        $s2 = "DownloadAndExecuteUpdate" wide
        $s3 = "CommandLineUpdate" wide
        $net1 = "IPEnabled" ascii wide
        $net2 = "SELECT * FROM Win32_OperatingSystem" ascii wide
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🛡️ YARA CLI Deployment:
```bash
yara -r redline.yar C:\\Users\\Public\\Downloads\\
```"""
        },
        {
            "title": "Spring4Shell Remote Code Execution (CVE-2022-22965)",
            "rule_type": "Sigma",
            "mitre_ttp": "T1190 - Exploit Public-Facing Application",
            "severity": "CRITICAL",
            "target_cve": "CVE-2022-22965",
            "target_siem": "Splunk / Sentinel",
            "description": "Detects ClassLoader manipulation parameters sent to Spring Framework web applications.",
            "code_content": """title: Spring4Shell ClassLoader Exploit Payload
id: sp4s-8812-4c91-9123-spring4shell
status: production
description: Detects ClassLoader properties in HTTP POST parameters targeting Spring4Shell.
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        c-uri-query|contains:
            - 'class.module.classLoader'
            - 'pipeline.first.pattern'
    condition: selection
level: critical""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟢 Elastic (EQL Query):
```eql
http where http.request.method == "POST" and http.request.body.content contains "class.module.classLoader"
```"""
        },
        {
            "title": "Volume Shadow Copy Deletion via Vssadmin / Wmic",
            "rule_type": "Sigma",
            "mitre_ttp": "T1490 - Inhibit System Recovery",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "Splunk / Sentinel / QRadar",
            "description": "Detects commands attempting to delete volume shadow copies to prevent system recovery prior to ransomware encryption.",
            "code_content": """title: Volume Shadow Copy Deletion Attempt
id: vss-9921-4f12-9912-shadowdel
status: production
description: Detects vssadmin, wmic, or powershell commands deleting shadow copies.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'vssadmin.exe delete shadows'
            - 'wmic shadowcopy delete'
            - 'Resize-Partition'
    condition: selection
level: high""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (SPL Query):
```spl
index=windows (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*")
| table _time, host, User, Process, CommandLine
```"""
        },
        {
            "title": "XZ Utils Backdoor SSH Authentication Bypass (CVE-2024-3094)",
            "rule_type": "Sigma",
            "mitre_ttp": "T1195.001 - Supply Chain Compromise",
            "severity": "CRITICAL",
            "target_cve": "CVE-2024-3094",
            "target_siem": "Splunk / Elastic",
            "description": "Detects execution of malicious liblzma library functions inside sshd process on Linux systems.",
            "code_content": """title: XZ Utils Backdoor SSH Malicious Liblzma Execution
id: xz-3094-4f12-9912-xzbackdoor
status: production
description: Detects SSH process memory hooks associated with CVE-2024-3094.
logsource:
    category: application
    product: linux
detection:
    selection:
        process.name: 'sshd'
        message|contains: 'RSA_public_decrypt'
    condition: selection
level: critical""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🐧 Linux Journald / Auditd Query:
```bash
journalctl -u ssh.service | grep -i "liblzma"
```"""
        },
        {
            "title": "Web Shell File Creation in IIS / NGINX / Apache Path",
            "rule_type": "Sigma",
            "mitre_ttp": "T1505.003 - Web Shell",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "Splunk / Sentinel / Elastic",
            "description": "Detects suspicious creation of .aspx, .php, or .jsp files inside web root directories by web server service accounts.",
            "code_content": """title: Web Shell Creation in Web Root Directory
id: a891c20e-8219-4c91-9123-webshell
status: production
description: Detects script creation in web application directories by w3wp.exe or httpd.
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
        TargetFilename|endswith:
            - '.aspx'
            - '.php'
            - '.jsp'
            - '.ashx'
    condition: selection
level: high""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🟠 Splunk (Sysmon Event Code 11 FileCreate):
```spl
index=windows EventCode=11 (Image="*\\w3wp.exe" OR Image="*\\httpd.exe")
(TargetFilename="*.aspx" OR TargetFilename="*.php" OR TargetFilename="*.jsp")
| table _time, host, Image, TargetFilename
```"""
        },
        {
            "title": "AgentTesla Infostealer Binary Signature",
            "rule_type": "YARA",
            "mitre_ttp": "T1555 - Credentials from Password Stores",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "YARA / Endpoint AV",
            "description": "YARA rule detecting AgentTesla keylogger and SMTP credential exfiltration code patterns.",
            "code_content": """rule AgentTesla_Infostealer {
    meta:
        description = "Detects AgentTesla keylogger binaries"
        author = "CyberDash CTI"
    strings:
        $s1 = "get_logins" ascii wide
        $s2 = "smtp.gmail.com" ascii wide
        $s3 = "ftp://ftp." ascii wide
        $s4 = "AccountConfiguration" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 🛡️ YARA CLI Scanning:
```bash
yara64.exe -r agenttesla.yar C:\\Users\\Public\\
```"""
        },
        {
            "title": "Qakbot (Qbot) DLL Hijacking Execution",
            "rule_type": "YARA",
            "mitre_ttp": "T1574.002 - DLL Side-Loading",
            "severity": "HIGH",
            "target_cve": "N/A",
            "target_siem": "YARA / EDR Scanner",
            "description": "Detects Qakbot DLL side-loading payloads and obfuscated loader stub structures.",
            "code_content": """rule Qakbot_DLL_SideLoading {
    meta:
        description = "Detects Qakbot malware DLL payloads"
        author = "CyberDash SecOps"
    strings:
        $q1 = "wermgr.exe" ascii wide
        $q2 = "schtasks.exe /create" ascii wide
        $q3 = { 8b 44 24 04 8b 4c 24 08 33 c0 85 c9 7e 0b 8b 10 03 d0 }
    condition:
        uint16(0) == 0x5A4D and 2 of ($q*)
}""",
            "deployment_guide": """### 🛠️ Product Deployment Instructions

#### 💻 Defender for Endpoint (MDE) Custom Detection:
1. Load YARA signature into Microsoft Defender Portal -> Custom Detection Rules.
2. Set execution action to *Quarantine File* and trigger alert for Security Operations."""
        }
    ]

    with get_connection() as conn:
        cursor = conn.cursor()
        for r in rules:
            cursor.execute("""
                INSERT OR IGNORE INTO detection_rules
                (title, rule_type, mitre_ttp, severity, target_cve, description, code_content, target_siem, deployment_guide)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r["title"],
                r["rule_type"],
                r["mitre_ttp"],
                r["severity"],
                r["target_cve"],
                r["description"],
                r["code_content"],
                r["target_siem"],
                r.get("deployment_guide", "")
            ))
            # Also update deployment_guide if rule already exists but has empty guide
            cursor.execute("""
                UPDATE detection_rules
                SET deployment_guide = ?
                WHERE title = ? AND (deployment_guide IS NULL OR deployment_guide = '')
            """, (r.get("deployment_guide", ""), r["title"]))

        # Cleanup any pre-existing duplicates by title
        cursor.execute("""
            DELETE FROM detection_rules
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM detection_rules
                GROUP BY LOWER(TRIM(title))
            )
        """)
        conn.commit()
