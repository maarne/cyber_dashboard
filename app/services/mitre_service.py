# ============================================================
# app/services/mitre_service.py — MITRE ATT&CK® Intelligence Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides metadata, tactics, technical descriptions, and last-modified
# dates for MITRE ATT&CK Enterprise techniques and sub-techniques.
# ============================================================

MITRE_TTP_DATABASE = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a vulnerability or weakness in an Internet-facing computer or program using software, package, or service exploits.",
        "last_modified": "2024-03-28",
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "last_modified": "2024-04-12",
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages with malicious attachments or links to induce targets into executing code or delivering credentials.",
        "last_modified": "2024-03-15",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries across target systems.",
        "last_modified": "2024-03-20",
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution, discovery, and automated lateral movement.",
        "last_modified": "2024-04-05",
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems, such as adding credentials, modifying permissions, or granting OAuth roles.",
        "last_modified": "2023-09-29",
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability of system and network resources, typically demanding extortion payment.",
        "last_modified": "2023-10-18",
    },
    "T1070": {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or alter generated artifacts on a host system, such as event logs, files, or registry keys, to conceal malicious activity.",
        "last_modified": "2024-03-28",
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid credentials to log in to services that accept remote connections, such as RDP, SSH, SMB, or WinRM.",
        "last_modified": "2023-12-14",
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or remove built-in system recovery points, Volume Shadow Copies, and backup configurations before deploying ransomware.",
        "last_modified": "2023-09-15",
    },
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": "An adversary may rely on actions by a user to gain execution, such as opening a malicious email attachment or clicking an exploit payload link.",
        "last_modified": "2023-04-10",
    },
    "T1547": {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence.",
        "last_modified": "2023-08-22",
    },
    "T1090": {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may construct and utilize multi-hop proxy chains, SOHO botnet proxies, or TOR networks to disguise command and control origins.",
        "last_modified": "2024-02-19",
    },
    "T1036": {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may manipulate features of their artifacts (such as file names, extensions, icons, or paths) to make them appear legitimate to users or security software.",
        "last_modified": "2024-03-01",
    },
    "T1505": {
        "id": "T1505",
        "name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Adversaries may abuse legitimate extensible features of servers (like IIS modules, web server extensions, or plugins) to establish backdoor persistence.",
        "last_modified": "2023-09-29",
    },
    "T1505.003": {
        "id": "T1505.003",
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may install Web shells on compromised web servers to maintain persistent administrative web access and execute arbitrary commands.",
        "last_modified": "2023-09-29",
    },
    "T1567": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data to a cloud storage service, file sharing site, or external API rather than their dedicated C2 infrastructure.",
        "last_modified": "2023-10-12",
    },
    "T1530": {
        "id": "T1530",
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversaries may extract data from cloud storage instances (like AWS S3, Azure Blob, or Google Cloud Storage) after obtaining compromised credentials.",
        "last_modified": "2023-03-18",
    },
    "T1621": {
        "id": "T1621",
        "name": "Multi-Factor Authentication Request Generation",
        "tactic": "Credential Access",
        "description": "Adversaries may issue repeated MFA push notifications (MFA fatigue/bombing) to a target's mobile device until the user inadvertently approves the prompt.",
        "last_modified": "2023-10-15",
    },
    "T1556": {
        "id": "T1556",
        "name": "Modify Authentication Process",
        "tactic": "Defense Evasion, Persistence, Credential Access",
        "description": "Adversaries may modify authentication mechanisms (like Windows Password Filter DLLs, PAM, or Azure AD SAML tokens) to intercept credentials or bypass MFA.",
        "last_modified": "2023-09-29",
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may dump credentials from the operating system to obtain plaintext passwords, NTLM password hashes, or Kerberos tickets.",
        "last_modified": "2024-03-15",
    },
    "T1003.001": {
        "id": "T1003.001",
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access and dump the memory of the Local Security Authority Subsystem Service (LSASS) process to obtain active credentials.",
        "last_modified": "2024-03-15",
    },
    "T1114": {
        "id": "T1114",
        "name": "Email Collection",
        "tactic": "Collection",
        "description": "Adversaries may target and collect email communications from mail servers (Exchange, M365) or local email client databases to acquire sensitive data.",
        "last_modified": "2023-09-29",
    },
    "T1485": {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and files on target systems with wiper malware to disrupt operations or render systems inoperable.",
        "last_modified": "2023-10-18",
    },
    "T1561": {
        "id": "T1561",
        "name": "Disk Wipe",
        "tactic": "Impact",
        "description": "Adversaries may wipe the contents of hard drives, Master Boot Records (MBR), or partition tables to completely destroy system recoverability.",
        "last_modified": "2023-09-15",
    },
    "T1014": {
        "id": "T1014",
        "name": "Rootkit",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use rootkits to hide the presence of programs, files, network connections, and system modifications from security monitors.",
        "last_modified": "2023-09-29",
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS, WebSockets) to avoid detection by blending with standard traffic.",
        "last_modified": "2024-03-28",
    },
    "T1189": {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing, exploiting browser vulnerabilities or waterholing.",
        "last_modified": "2023-03-30",
    },
    "T1553": {
        "id": "T1553",
        "name": "Subvert Trust Controls",
        "tactic": "Defense Evasion",
        "description": "Adversaries may undermine security controls by stealing code signing certificates, modifying trust stores, or bypassing Mark-of-the-Web (MOTW).",
        "last_modified": "2023-10-25",
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "last_modified": "2024-03-28",
    },
    "T1195": {
        "id": "T1195",
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer to compromise data or systems.",
        "last_modified": "2023-09-29",
    },
    "T1195.001": {
        "id": "T1195.001",
        "name": "Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
        "description": "Adversaries may manipulate dependencies, packages, open source repositories, or build tools prior to compilation or delivery.",
        "last_modified": "2024-04-01",
    },
    "T1040": {
        "id": "T1040",
        "name": "Network Sniffing",
        "tactic": "Credential Access, Discovery",
        "description": "Adversaries may sniff network traffic in order to capture authentication credentials, unencrypted secrets, or network topology data.",
        "last_modified": "2023-09-15",
    },
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local system storage (e.g., file systems, directories, user documents) to find sensitive files of interest.",
        "last_modified": "2023-03-15",
    },
    "T1091": {
        "id": "T1091",
        "name": "Replication Through Removable Media",
        "tactic": "Initial Access, Lateral Movement",
        "description": "Adversaries may move onto systems, including air-gapped networks, by copying malware to USB drives and auto-executing on connection.",
        "last_modified": "2023-09-15",
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised network to expand their toolset.",
        "last_modified": "2023-10-18",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on host or network devices to identify reachable targets and exploitable versions.",
        "last_modified": "2023-09-15",
    },
    "T1176": {
        "id": "T1176",
        "name": "Browser Extensions",
        "tactic": "Persistence",
        "description": "Adversaries may abuse browser extensions to establish persistent access to systems and monitor web traffic or steal session tokens.",
        "last_modified": "2023-09-29",
    },
    "T1539": {
        "id": "T1539",
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "description": "Adversaries may steal web application session cookies from browser memory or local storage to bypass authentication prompts and MFA.",
        "last_modified": "2023-09-29",
    },
    "T1219": {
        "id": "T1219",
        "name": "Remote Access Software",
        "tactic": "Command and Control",
        "description": "Adversaries may use legitimate remote monitoring and management (RMM) software (e.g. AnyDesk, TeamViewer, ScreenConnect) for stealthy C2.",
        "last_modified": "2024-02-10",
    },
    "T1555": {
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Adversaries may search for common password storage locations, web browser vaults, or password manager databases to harvest stored secrets.",
        "last_modified": "2023-09-29",
    },
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify, disable, or uninstall security tools (antivirus, EDR agents, firewalls) to avoid detection.",
        "last_modified": "2024-03-28",
    },
    "T1574.002": {
        "id": "T1574.002",
        "name": "DLL Side-Loading",
        "tactic": "Persistence, Privilege Escalation, Defense Evasion",
        "description": "Adversaries may execute their own malicious payloads by placing a rogue DLL in the same folder as a trusted signed executable.",
        "last_modified": "2023-10-18",
    },
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities (like kernel bugs or unquoted paths) to elevate privileges from standard user to SYSTEM or root.",
        "last_modified": "2023-09-29",
    },
}


def get_mitre_ttp_details(ttp_id: str) -> dict:
    """
    Lookup detailed metadata for a given MITRE ATT&CK TTP ID.
    Returns default metadata if the exact technique ID is not pre-cataloged.
    """
    clean_id = ttp_id.strip().split('-')[0].strip().upper()
    if clean_id in MITRE_TTP_DATABASE:
        return MITRE_TTP_DATABASE[clean_id]
    
    # Fallback heuristic for uncataloged techniques
    return {
        "id": clean_id,
        "name": f"Technique {clean_id}",
        "tactic": "Enterprise Attack",
        "description": f"MITRE ATT&CK Enterprise Technique {clean_id}. View full documentation and detection guidance on attack.mitre.org.",
        "last_modified": "2024-01-15",
    }
