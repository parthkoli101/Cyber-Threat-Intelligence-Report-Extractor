import sys
import os

filepath = r'c:\Users\Parth Koli\Downloads\cyber-report-analyzer\nlp_engine.py'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Chunk 1: Imports
content = content.replace(
    'from sklearn.metrics.pairwise import cosine_similarity',
    'from sklearn.metrics.pairwise import cosine_similarity\nimport pytesseract\nfrom PIL import Image\nimport io\nimport requests\nimport json\nimport os\nfrom transformers import pipeline'
)

# Chunk 2: Techniques
tech_old = '''TECHNIQUES = """T1566|Phishing|Initial Access|phishing emails with malicious attachments or links sent to victims
T1190|Exploit Public-Facing Application|Initial Access|exploiting a vulnerability in an internet-facing web application or server
T1133|External Remote Services|Initial Access|using VPN or remote desktop services exposed to the internet to gain access
T1078|Valid Accounts|Initial Access|using stolen or compromised legitimate credentials and accounts to log in
T1195|Supply Chain Compromise|Initial Access|compromising a software supplier or third party vendor update to reach victims
T1189|Drive-by Compromise|Initial Access|victim visits a compromised or malicious website that delivers malware
T1059|Command and Scripting Interpreter|Execution|running commands or malicious scripts using PowerShell, cmd, bash or Python
T1204|User Execution|Execution|user opens a malicious file or clicks a link that runs malware
T1047|Windows Management Instrumentation|Execution|using WMI to execute commands remotely
T1053|Scheduled Task/Job|Execution|creating scheduled tasks or cron jobs to run malware
T1569|System Services|Execution|running malware as a service or with PsExec
T1547|Boot or Logon Autostart Execution|Persistence|registry run keys or startup folder entries to keep malware running after reboot
T1136|Create Account|Persistence|creating new user or administrator accounts for persistent access
T1505|Server Software Component|Persistence|installing a web shell on a web server
T1543|Create or Modify System Process|Persistence|installing a malicious service that starts automatically
T1098|Account Manipulation|Persistence|adding permissions or changing credentials of accounts
T1068|Exploitation for Privilege Escalation|Privilege Escalation|exploiting a vulnerability to gain higher privileges on a system
T1548|Abuse Elevation Control Mechanism|Privilege Escalation|bypassing UAC or sudo to elevate privileges
T1055|Process Injection|Defense Evasion|injecting malicious code into legitimate running processes
T1562|Impair Defenses|Defense Evasion|disabling antivirus, EDR, security tools or logging
T1070|Indicator Removal|Defense Evasion|deleting logs and files to hide attacker activity
T1027|Obfuscated Files or Information|Defense Evasion|obfuscated, packed or encoded payloads
T1036|Masquerading|Defense Evasion|malware disguised as legitimate file or process names
T1218|System Binary Proxy Execution|Defense Evasion|abusing signed built-in binaries like rundll32 or mshta to run code
T1003|OS Credential Dumping|Credential Access|dumping credentials from LSASS memory or the password database with Mimikatz
T1110|Brute Force|Credential Access|password guessing, password spraying or credential stuffing attempts
T1555|Credentials from Password Stores|Credential Access|stealing saved passwords from browsers or password managers
T1056|Input Capture|Credential Access|keylogging to capture typed passwords
T1558|Steal or Forge Kerberos Tickets|Credential Access|kerberoasting or golden ticket attacks
T1087|Account Discovery|Discovery|enumerating user and domain accounts
T1018|Remote System Discovery|Discovery|scanning the network to find other hosts and servers
T1046|Network Service Discovery|Discovery|port scanning to find open services
T1083|File and Directory Discovery|Discovery|searching for files and folders of interest
T1021|Remote Services|Lateral Movement|moving laterally using RDP, SMB, SSH or other remote services
T1570|Lateral Tool Transfer|Lateral Movement|copying tools and malware between systems inside the network
T1550|Use Alternate Authentication Material|Lateral Movement|pass the hash or pass the ticket
T1560|Archive Collected Data|Collection|compressing and encrypting data with zip or rar before exfiltration
T1005|Data from Local System|Collection|collecting sensitive files from local systems
T1114|Email Collection|Collection|accessing mailboxes to read or collect email
T1071|Application Layer Protocol|Command and Control|command and control traffic over HTTP, HTTPS or DNS
T1105|Ingress Tool Transfer|Command and Control|downloading additional tools or payloads from attacker servers
T1573|Encrypted Channel|Command and Control|encrypted communication with the command and control server
T1219|Remote Access Software|Command and Control|using legitimate remote access tools such as AnyDesk or TeamViewer
T1090|Proxy|Command and Control|routing traffic through proxies or tunnels
T1041|Exfiltration Over C2 Channel|Exfiltration|stealing data by sending it over the command and control channel
T1567|Exfiltration Over Web Service|Exfiltration|uploading stolen data to cloud storage or file sharing sites
T1048|Exfiltration Over Alternative Protocol|Exfiltration|exfiltrating data over FTP, DNS or other protocols
T1486|Data Encrypted for Impact|Impact|encrypting files with ransomware and demanding a ransom
T1490|Inhibit System Recovery|Impact|deleting backups and shadow copies and disabling recovery
T1489|Service Stop|Impact|stopping services and databases
T1498|Network Denial of Service|Impact|flooding a network to cause a denial of service
T1485|Data Destruction|Impact|wiping or destroying data
T1657|Financial Theft|Impact|stealing money through fraudulent wire transfers"""
TECH = [tuple(l.split("|")) for l in TECHNIQUES.splitlines()]
TECH_BY_ID = {t[0]: t for t in TECH}'''

tech_new = '''TECH = []
TECH_BY_ID = {}

def _init_mitre():
    global TECH, TECH_BY_ID
    if TECH: return
    cache_path = "mitre_cache.json"
    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception:
            data = {"objects": []}
            
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            tid = next((r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
            if tid:
                name = obj.get("name", "")
                desc = obj.get("description", "")
                kcp = obj.get("kill_chain_phases", [])
                tactic = kcp[0]["phase_name"].replace("-", " ").title() if kcp else "Unknown"
                if tactic == "Privilege Escalation": tactic = "Privilege Escalation"
                t = (tid, name, tactic, desc)
                TECH.append(t)
                TECH_BY_ID[tid] = t'''

if tech_old in content:
    content = content.replace(tech_old, tech_new)
else:
    print("Could not find chunk 2 (TECHNIQUES).")

# Chunk 3: load_models
lm_old = '''_NLP = None
_EMB = None
_EMB_TRIED = False
_TECH_VEC = None
_TYPE_VEC = None
_TYPE_KEYS = None


def load_models():
    global _NLP
    if _NLP is None:
        try:
            _NLP = spacy.load("en_core_web_sm", disable=["parser"])
        except OSError:
            raise RuntimeError("spaCy model missing. Run: python -m spacy download en_core_web_sm")
        if "sentencizer" not in _NLP.pipe_names:
            _NLP.add_pipe("sentencizer", first=True)
    _embedder()
    _cache_vectors()'''

lm_new = '''_NLP = None
_EMB = None
_EMB_TRIED = False
_TECH_VEC = None
_TYPE_VEC = None
_TYPE_KEYS = None
_NER_MODEL = None

def load_models():
    global _NLP, _NER_MODEL
    _init_mitre()
    if _NLP is None:
        try:
            _NLP = spacy.load("en_core_web_sm", disable=["parser"])
        except OSError:
            raise RuntimeError("spaCy model missing. Run: python -m spacy download en_core_web_sm")
        if "sentencizer" not in _NLP.pipe_names:
            _NLP.add_pipe("sentencizer", first=True)
    if _NER_MODEL is None:
        try:
            _NER_MODEL = pipeline("ner", model="d4data/en-cybersecurity-ner", aggregation_strategy="simple")
        except Exception as e:
            print(f"[nlp_engine] NER pipeline unavailable ({e}); falling back to basic extraction.")
    _embedder()
    _cache_vectors()'''
if lm_old in content:
    content = content.replace(lm_old, lm_new)
else:
    print("Could not find chunk 3 (load_models).")

# Chunk 4: extract_pages
ex_old = '''def extract_pages(pdf_bytes):
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        raise ValueError("This file could not be opened as a PDF. It may be corrupted.")
    try:
        if doc.needs_pass:
            raise ValueError("This PDF is password protected. Please upload an unprotected copy.")
        if doc.page_count == 0:
            raise ValueError("This PDF has no pages.")
        pages = [(i + 1, p.get_text("text")) for i, p in enumerate(doc)]
        blob = "".join(t for _, t in pages)
        if not blob.strip():
            if any(p.get_images() for p in doc):
                raise ValueError("This looks like a scanned PDF: it contains images but no extractable text. "
                                 "Please upload a text-based PDF (OCR is not included).")
            raise ValueError("This PDF is empty: no text could be found.")
        return pages
    finally:
        doc.close()'''

ex_new = '''def extract_pages(pdf_bytes):
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        raise ValueError("This file could not be opened as a PDF. It may be corrupted.")
    try:
        if doc.needs_pass:
            raise ValueError("This PDF is password protected. Please upload an unprotected copy.")
        if doc.page_count == 0:
            raise ValueError("This PDF has no pages.")
        
        pages = []
        for i, p in enumerate(doc):
            blocks = p.get_text("blocks")
            blocks.sort(key=lambda b: (b[1], b[0]))
            text_content = "\\n".join([b[4] for b in blocks if b[6] == 0])
            
            try:
                for img in p.get_images():
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image = Image.open(io.BytesIO(image_bytes))
                    text_content += "\\n" + pytesseract.image_to_string(image)
            except Exception:
                pass
            
            pages.append((i + 1, text_content))
            
        blob = "".join(t for _, t in pages)
        if not blob.strip():
            raise ValueError("This PDF is empty: no text could be found.")
        return pages
    finally:
        doc.close()'''
if ex_old in content:
    content = content.replace(ex_old, ex_new)
else:
    print("Could not find chunk 4 (extract_pages).")

# Chunk 5 & 6: Expand IOC Types
re_old = '''RE_TECH_ID = re.compile(r"\\bT(\\d{4})(?:\\.\\d{3})?\\b")'''
re_new = '''RE_TECH_ID = re.compile(r"\\bT(\\d{4})(?:\\.\\d{3})?\\b")
RE_BTC = re.compile(r"\\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\\b")
RE_XMR = re.compile(r"\\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\\b")
RE_REGISTRY = re.compile(r"\\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\\\[a-zA-Z0-9_\\\\ \\-]+\\b", re.I)
RE_FILEPATH_WIN = re.compile(r"\\b(?:[a-zA-Z]:|\\\\\\\\)\\\\[a-zA-Z0-9_\\\\\\-\\.\\s]+\\.\\w+\\b")
RE_FILEPATH_LINUX = re.compile(r"(?:\\/[a-zA-Z0-9_.\\-]+)+\\b")'''
if re_old in content:
    content = content.replace(re_old, re_new)
else:
    print("Could not find chunk 5 (regexes).")

ioc_old = '''        t_wo = RE_IPV4.sub(" ", t_wo)
        if pno in ioc_pages:
            for d in (m.group(0) for m in RE_DOMAIN.finditer(t_wo)):
                if _ok_domain(d) and keep_net(pno, raw, d, "Domain"):
                    add("Domain", d.lower(), "", pno, raw)
    return list(found.values())'''
ioc_new = '''        t_wo = RE_IPV4.sub(" ", t_wo)
        
        for w in RE_BTC.findall(t_wo):
            add("Bitcoin address", w, "", pno, raw)
        for w in RE_XMR.findall(t_wo):
            add("Monero address", w, "", pno, raw)
        for w in RE_REGISTRY.findall(t_wo):
            add("Registry Key", w, "", pno, raw)
        for w in RE_FILEPATH_WIN.findall(t_wo):
            add("File Path (Windows)", w, "", pno, raw)
        for w in RE_FILEPATH_LINUX.findall(t_wo):
            if len(w) > 6 and not re.match(r"^\\/\\d{4}\\/\\d{2}", w):
                add("File Path (Linux)", w, "", pno, raw)
                
        if pno in ioc_pages:
            for d in (m.group(0) for m in RE_DOMAIN.finditer(t_wo)):
                if _ok_domain(d) and keep_net(pno, raw, d, "Domain"):
                    add("Domain", d.lower(), "", pno, raw)
    return list(found.values())'''
if ioc_old in content:
    content = content.replace(ioc_old, ioc_new)
else:
    print("Could not find chunk 6 (ioc matching).")

# Chunk 7: extract_actors
act_old = '''    for s in sents:
        if _is_noise_sent(s):
            continue
        t = s["text"]
        for m in RE_SWID.finditer(t):'''
act_new = '''    for s in sents:
        if _is_noise_sent(s):
            continue
        t = s["text"]
        
        if _NER_MODEL is not None:
            try:
                ner_res = _NER_MODEL(t)
                for ent in ner_res:
                    grp = ent["entity_group"]
                    if grp in ("MALWARE", "THREAT_ACTOR"):
                        typ = "Malware / tool" if grp == "MALWARE" else "Threat actor"
                        add_name(ent["word"], typ, grp, s)
            except Exception:
                pass
                
        for m in RE_SWID.finditer(t):'''
if act_old in content:
    content = content.replace(act_old, act_new)
else:
    print("Could not find chunk 7 (extract_actors).")

# Chunk 8: IOC meaning
iocm_old = '''IOC_GROUP = {"IPv4 address": "IP addresses", "IPv6 address": "IP addresses", "Domain": "Domains", "URL": "URLs",
             "MD5 hash": "File hashes", "SHA1 hash": "File hashes", "SHA256 hash": "File hashes",
             "Email address": "Email addresses", "CVE": "CVE IDs"}
IOC_MEANING = {
    "Domains": "suggesting the attack relied mostly on malicious web infrastructure",
    "IP addresses": "so blocking or hunting on network addresses is the most direct defensive use of this report",
    "URLs": "pointing to specific payload or command-and-control paths that can be blocked at the proxy",
    "File hashes": "so file-based artefacts dominate and endpoint detection by hash is the main way to use this report",
    "Email addresses": "which points to email as an important part of the attack",
    "CVE IDs": "which shows the incident is centred on known vulnerabilities that need patching",
}'''
iocm_new = '''IOC_GROUP = {"IPv4 address": "IP addresses", "IPv6 address": "IP addresses", "Domain": "Domains", "URL": "URLs",
             "MD5 hash": "File hashes", "SHA1 hash": "File hashes", "SHA256 hash": "File hashes",
             "Email address": "Email addresses", "CVE": "CVE IDs",
             "Bitcoin address": "Cryptocurrency", "Monero address": "Cryptocurrency",
             "Registry Key": "System Artifacts", "File Path (Windows)": "System Artifacts", "File Path (Linux)": "System Artifacts"}
IOC_MEANING = {
    "Domains": "suggesting the attack relied mostly on malicious web infrastructure",
    "IP addresses": "so blocking or hunting on network addresses is the most direct defensive use of this report",
    "URLs": "pointing to specific payload or command-and-control paths that can be blocked at the proxy",
    "File hashes": "so file-based artefacts dominate and endpoint detection by hash is the main way to use this report",
    "Email addresses": "which points to email as an important part of the attack",
    "CVE IDs": "which shows the incident is centred on known vulnerabilities that need patching",
    "Cryptocurrency": "highlighting financial extortion vectors often seen in ransomware",
    "System Artifacts": "indicating host-level configuration changes and persistence mechanisms",
}'''
if iocm_old in content:
    content = content.replace(iocm_old, iocm_new)
else:
    print("Could not find chunk 8 (IOC meaning).")

ioct_old = '''    ioc_tabs = []
    for typ in ("IPv4 address", "IPv6 address", "Domain", "URL", "MD5 hash", "SHA1 hash", "SHA256 hash",
                "Email address", "CVE"):'''
ioct_new = '''    ioc_tabs = []
    for typ in ("IPv4 address", "IPv6 address", "Domain", "URL", "MD5 hash", "SHA1 hash", "SHA256 hash",
                "Email address", "CVE", "Bitcoin address", "Monero address", "Registry Key", "File Path (Windows)", "File Path (Linux)"):'''
if ioct_old in content:
    content = content.replace(ioct_old, ioct_new)
else:
    print("Could not find chunk 9 (IOC tabs).")


with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("Update successful!")
