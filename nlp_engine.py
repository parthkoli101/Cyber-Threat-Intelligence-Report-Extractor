"""
Cyber Incident Report Analyzer — classical NLP (offline, no LLM).

Pipeline: PDF pages -> spaCy sentences -> IOCs / actors / ATT&CK / timeline /
impact / response / gaps -> templated report.

Setup (once):
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm
First run downloads all-MiniLM-L6-v2 (~90 MB); later runs are offline.
"""
import datetime as dt
import re
import ipaddress
from collections import Counter, OrderedDict
from urllib.parse import urlparse

import fitz
import numpy as np
import spacy
import dateparser
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pytesseract
from PIL import Image
import io
import requests
import json
import os
from transformers import pipeline

NO_DATA = "No relevant data found"

# --------------------------------------------------------------------------
# ATT&CK catalog (framework knowledge, not report-specific names)
# --------------------------------------------------------------------------
TECH = []
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
                TECH_BY_ID[tid] = t
TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
                "Exfiltration", "Impact"]
# Initial-access techniques -> human vector labels (derived from ATT&CK, not a report list)
TECH_TO_VECTOR = {
    "T1566": "Phishing email",
    "T1190": "Exploitation of a vulnerability",
    "T1078": "Stolen or weak credentials",
    "T1110": "Stolen or weak credentials",
    "T1133": "Exposed remote access (RDP/VPN)",
    "T1195": "Supply chain / third party",
    "T1189": "Drive-by / malicious website",
}
ATTACK_TYPE_DESC = OrderedDict([
    ("Ransomware", "ransomware encrypts files demands ransom decryptor double extortion leak site"),
    ("Phishing", "phishing spear-phishing malicious email credential harvesting lure"),
    ("Credential theft", "credential dumping password spraying brute force infostealer mimikatz stolen passwords"),
    ("Vulnerability exploitation", "exploit CVE remote code execution unpatched public-facing vulnerability zero-day"),
    ("Data breach / exfiltration", "exfiltration data theft stolen data leak uploaded to cloud"),
    ("Malware infection", "malware trojan backdoor loader worm implant ransomware affiliate tool"),
    ("DDoS", "distributed denial of service botnet flood availability"),
    ("Supply chain attack", "supply chain trojanized software update third-party vendor compromise"),
    ("Business email compromise", "business email compromise invoice fraud wire transfer mailbox"),
    ("Espionage / APT", "espionage nation-state strategic intelligence persistent access"),
    ("Web application attack", "web shell XSS SQL injection defacement webshell"),
    ("Insider threat", "malicious insider rogue employee abuse of legitimate access"),
])
# Asset phrases are infrastructure language, not victim names
ASSET_PATTERNS = OrderedDict([
    ("Domain controller / Active Directory", r"domain controllers?|active directory"),
    ("Email server", r"exchange servers?|mail servers?|email servers?|mailboxes?"),
    ("VPN gateway / appliance", r"\bvpn (?:gateway|appliance|server|concentrator)s?|\bssl-?vpn\b|\bvpn\b"),
    ("Web server / application", r"web servers?|web applications?|web portals?|confluence|sharepoint"),
    ("Database", r"databases?|sql servers?"),
    ("File server / shares", r"file servers?|file shares?|network shares?"),
    ("Backups", r"backups?|volume shadow copies|shadow copies"),
    ("Virtualisation (ESXi / VMs)", r"esxi|hypervisors?|virtual machines?"),
    ("Workstations / endpoints", r"workstations?|laptops?|endpoints?|desktops?|user endpoints?"),
    ("Cloud storage / tenant", r"cloud (?:storage|environment|tenant|account|infrastructure)|s3 buckets?"),
    ("Firewall / network devices", r"firewalls?|routers?|network devices?"),
    ("ERP / CRM / business systems", r"\berp\b|\bcrm\b|payment systems?|point[- ]of[- ]sale"),
    ("Industrial / OT systems", r"scada|industrial control|\bics\b|ot network"),
    ("Servers (general)", r"\bservers?\b"),
])

# --------------------------------------------------------------------------
# Linguistic cues (not entity names)
# --------------------------------------------------------------------------
REC_MODAL = re.compile(
    r"\b(should|recommend\w*|advis\w*|urge\w*|must|need to|needs to|ought to|best practices?|"
    r"it is important to|encouraged|strongly suggest\w*|consider)\b", re.I)
REC_ACTION = re.compile(
    r"\b(patch\w*|block\w*|isolat\w*|reset\w*|mfa|multi-?factor|two-?factor|2fa|segment\w*|back-?ups?|"
    r"updat\w*|monitor\w*|restrict\w*|disabl\w*|enabl\w*|password\w*|credential\w*|train\w*|"
    r"least privilege|firewall\w*|filter\w*|audit\w*|review\w*|implement\w*|appl(?:y|ied)|deploy\w*|"
    r"encrypt\w*|contain\w*|remediat\w*|mitigat\w*|limit\w*|enforc\w*|logging|edr|allow-?list\w*|"
    r"whitelist\w*|access control\w*|vulnerabilit\w*|upgrad\w*|scan\w*|harden\w*|rotate|revoke)\b", re.I)
REC_IMPERATIVE = re.compile(
    r"^(?:[\u2022\-\*\u2013\u25aa\u25cf]\s*|\d+[\.\)]\s*)?(patch|block|isolate|reset|enable|apply|"
    r"update|disable|implement|monitor|review|restrict|segment|enforce|require|ensure|maintain|"
    r"conduct|use|deploy|limit|audit|train|verify|change|rotate|revoke|remove|keep|install|"
    r"configure|create|test|store|encrypt|do not|never|avoid)\b(?!\s+of\b)(?!:)", re.I)
RESP_VERB = re.compile(
    r"\b(isolated|contained|blocked|disabled|reset|revoked|patched|restored|shut down|shut off|notified|"
    r"engaged|remediated|removed|quarantined|rebuilt|taken offline|took [^.]{0,25}offline|reported to|"
    r"mitigated|terminated|reimaged|re-imaged|recovered|eradicated|activated|initiated|informed|alerted|"
    r"deactivated|wiped|rotated|implemented|deployed|applied|enabled|escalated|hired|brought in)\b", re.I)
DEFENDER = re.compile(
    r"\b(we|our|the (?:company|organi[sz]ation|victim|it team|soc|security team|incident response team|"
    r"response team|administrators?|management|engineers?)|responders?|defenders?|ir team|cert|"
    r"upon detection|immediately|promptly|in response|after (?:detection|discovery))\b", re.I)
ATTACKER = re.compile(
    r"\b(attackers?|threat actors?|adversar\w+|intruders?|hackers?|affiliates?|operators?|"
    r"ransomware (?:group|gang|variant)|the malware)\b", re.I)
HEDGE = re.compile(
    r"\b(may|might|could|likely|unlikely|possibly|possible|probably|suspect\w*|appears? to|appeared to|"
    r"believed|believe|thought to|potentially|reportedly|allegedly|linked to|associated with|consistent "
    r"with|similar to|overlaps?|resembl\w+|(?:low|moderate|medium) confidence|unconfirmed)\b", re.I)
CONFIRM = re.compile(
    r"\b(carried out by|conducted by|attributed to|claimed responsibility|responsible for|was behind|"
    r"were behind|perpetrated by|identified as the (?:actor|group|attacker)|high confidence|took credit|"
    r"confirmed (?:to be|as)|with (?:high|moderate) confidence)\b", re.I)
ATTR_CUE = re.compile(
    r"attribut|linked to|responsible for|behind (?:the|this)|carried out by|conducted by|nation-?state|"
    r"state-sponsored|associated with|perpetrat|affiliates? from", re.I)
VICTIM_CUE = re.compile(r"\b(victim|targeted|affected|impacted|breached|compromised|attacked)\b", re.I)
FOOTER = re.compile(r"\bTLP:|Page \d+\s+of\s+\d+|Product ID:|traffic light protocol\b", re.I)
BOILER = re.compile(
    r"\b(to report suspicious|contact your local|operations center|authoring organi[sz]ations|"
    r"for more information on the traffic light|no obligation to respond|disclaimer:|"
    r"visit \w+\.gov to see)\b", re.I)
IOC_SECTION = re.compile(
    r"\b(indicators? of compromise|\biocs?\b|known urls?|web requests?|ip address(?:es)?|"
    r"file hashes?|email addresses? related|malicious (?:domains?|urls?|infrastructure))\b", re.I)
TTP_CUE = re.compile(
    r"\b(phish|spear-?phish|exploit|vulnerabilit|encrypt|exfiltrat|lateral|credential|ransom|"
    r"command[- ]and[- ]control|\bc2\b|persist|privilege|dump|spray|shadow cop|remote desktop|"
    r"powershell|valid accounts?|disable.{0,20}(?:edr|antivirus)|backdoor|web shell)\b", re.I)
PAYLOAD_URL = re.compile(r"\.(?:exe|dll|bin|ps1|js|msi|zip|rar|hta|bat|cmd|scr|apk|elf)(?:\b|$|\?)", re.I)
NAME_STOP = {
    "the", "this", "that", "windows", "microsoft", "linux", "cisco", "table", "page", "clear",
    "https", "http", "appendix", "overview", "summary", "technique", "title", "use", "following",
    "initial", "access", "privilege", "escalation", "lateral", "movement", "data", "exfiltration",
    "indicators", "compromise", "mitigations", "detection", "disclaimer", "product", "joint",
    "advisory", "information", "security", "agency", "federal", "bureau",
}

MON = r"January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sept|Sep|Oct|Nov|Dec"
D_ISO = r"\b\d{4}-\d{2}-\d{2}\b"
D_DMY = rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:{MON})\.?,?\s+\d{{4}}\b"
D_MDY = rf"\b(?:{MON})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}\b"
D_MY = rf"\b(?:{MON})\.?,?\s+\d{{4}}\b"
RE_DATE = re.compile("|".join(f"(?:{p})" for p in (D_ISO, D_DMY, D_MDY, D_MY)), re.I)
PRECISE = [re.compile(p, re.I) for p in (D_ISO, D_DMY, D_MDY)]
COMPROMISE = re.compile(
    r"gained access|initial access|initially (?:compromised|accessed)|first (?:compromis|access|breach|intrusion)|"
    r"breached|compromised|infiltrat\w+|intrusion (?:began|started|occurred)|entered", re.I)
DETECT = re.compile(r"detect\w*|discover\w*|identified|noticed|alert\w*|became aware|observed|flagged|spotted", re.I)

NUM = r"(\d[\d,]*(?:\.\d+)?)"
MULT = {"thousand": 1e3, "k": 1e3, "million": 1e6, "mn": 1e6, "m": 1e6, "billion": 1e9, "bn": 1e9, "b": 1e9,
        "lakh": 1e5, "lakhs": 1e5, "crore": 1e7, "crores": 1e7}
RE_DATA = re.compile(rf"{NUM}\s?(PB|TB|GB|MB|petabytes?|terabytes?|gigabytes?|megabytes?)\b", re.I)
RE_COUNT = re.compile(
    rf"{NUM}\s?(thousand|million|billion|lakhs?|crores?)?\s?(?:[A-Za-z]+\s){{0,2}}?"
    r"(records|users|customers|employees|accounts|patients|individuals|people|files|devices|systems|"
    r"endpoints|servers|machines|mailboxes|credentials|victims|organi[sz]ations|companies)\b", re.I)
RE_DUR = re.compile(rf"{NUM}\s?(minutes?|hours?|days?|weeks?)\b", re.I)
DOWNTIME_CUE = re.compile(r"down|outage|offline|unavailab|disrupt|interrupt|halt|suspend|restor|recover|inaccessible", re.I)
RE_MONEY1 = re.compile(
    rf"(USD|US\$|\$|INR|Rs\.?|\u20b9|EUR|\u20ac|GBP|\u00a3)\s?{NUM}(?:\s?((?:million|billion|thousand|lakhs?|crores?|bn|mn)\b)|([MKB])\b)?",
    re.I)
RE_MONEY2 = re.compile(
    rf"{NUM}\s?(million|billion|thousand|lakhs?|crores?)?\s?(USD|dollars|INR|rupees|EUR|euros|GBP|pounds)\b", re.I)
CUR = {"usd": "USD", "us$": "USD", "$": "USD", "dollars": "USD", "inr": "INR", "rs": "INR", "rs.": "INR", "\u20b9": "INR",
       "rupees": "INR", "eur": "EUR", "\u20ac": "EUR", "euros": "EUR", "gbp": "GBP", "\u00a3": "GBP", "pounds": "GBP"}

TLDS = ("com|net|org|io|ru|cn|info|biz|xyz|top|site|online|co|us|uk|de|fr|in|gov|edu|cc|tk|ml|ga|cf|gq|pw|ws|su|me|tv|"
        "app|dev|cloud|live|club|shop|tech|icu|vip|work|link|click|ir|kp|ua|br|nl|it|es|jp|kr|au|ca|ch|se|pl|to|sh|"
        "onion|store|space|website|pro|mobi|name|cyou|buzz|rest|fun")
RE_URL = re.compile(r"\bhttps?://[^\s<>\"'\)\]\}]+", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_HASH = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
RE_IPV6 = re.compile(r"(?<![:\w])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?![:\w])")
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s)\b" % "|".join(sorted(TLDS.split("|"), key=len, reverse=True)),
    re.I)
RE_TECH_ID = re.compile(r"\bT(\d{4})(?:\.\d{3})?\b")
RE_BTC = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
RE_REGISTRY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\ \-]+\b", re.I)
RE_FILEPATH_WIN = re.compile(r"\b(?:[a-zA-Z]:|\\\\)\\[a-zA-Z0-9_\\\-\.\s]+\.\w+\b")
RE_FILEPATH_LINUX = re.compile(r"(?:\/[a-zA-Z0-9_.\-]+)+\b")
RE_SWID = re.compile(r"\b([A-Za-z][A-Za-z0-9][A-Za-z0-9+._-]{1,40})\s*\[S\d{4}(?:\.\d{3})?\]")
RE_RANSOM_NAME = re.compile(
    r"\b([A-Z][A-Za-z0-9+]{2,}(?:[ -][A-Z][A-Za-z0-9+]{2,}){0,2})\s+"
    r"(?:is |are |was |were )?(?:a |an )?"
    r"(?:ransomware(?:-as-a-service)?|raas|encryptor)\b", re.I)
RE_AKA = re.compile(
    r"(?:formerly|also|previously)\s+known as\s+([A-Z][A-Za-z0-9]+(?:\s*,\s*|\s+and\s+|\s+or\s+[A-Z][A-Za-z0-9]+)*)")
RE_SUCH_AS = re.compile(
    r"(?:variants?|families|groups?|actors?|affiliates? from(?: other)?(?: prominent)? variants?)\s+"
    r"such as\s+([A-Z][A-Za-z0-9]+(?:\s*,\s*[A-Z][A-Za-z0-9]+)*(?:\s+and\s+[A-Z][A-Za-z0-9]+)?)", re.I)
RE_APT = re.compile(r"\b(?:APT|UNC|TA|FIN)[ -]?\d{1,5}\b")
RE_GROUP_NAMED = re.compile(
    r"\b(?:threat actor|apt group|hacking group|ransomware (?:group|gang|family|variant)|cybercrime group|"
    r"group known as|cluster)\s+(?:known as |called |named |tracked as )?"
    r"([A-Z][A-Za-z0-9][A-Za-z0-9 .'-]{1,40}?)(?=\s+(?:is|has|was|were|used|and|,|\.|$))", re.I)
RE_MALWARE_KIND = re.compile(
    r"\b([A-Z][A-Za-z0-9+]{2,}(?:[ -][A-Z][A-Za-z0-9+]{2,}){0,2})\s+"
    r"(?:malware|trojan|backdoor|stealer|rat|botnet|wiper|loader|infostealer|spyware)\b", re.I)
SKIP_TITLE = re.compile(
    r"^(tlp:|to report|http|www\.|page \d|product id|for more information|download|contents)\b", re.I)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net", "example.edu", "test.com", "localhost")
ASSET_RX = [(name, re.compile(rx, re.I)) for name, rx in ASSET_PATTERNS.items()]

# --------------------------------------------------------------------------
# Models (loaded once; ATT&CK / type embeddings cached)
# --------------------------------------------------------------------------
_NLP = None
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
    _cache_vectors()


def _embedder():
    global _EMB, _EMB_TRIED
    if not _EMB_TRIED:
        _EMB_TRIED = True
        try:
            from sentence_transformers import SentenceTransformer
            _EMB = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception as e:
            print(f"[nlp_engine] sentence-transformers unavailable ({type(e).__name__}); TF-IDF fallback for mapping.")
    return _EMB


def _cache_vectors():
    global _TECH_VEC, _TYPE_VEC, _TYPE_KEYS
    emb = _embedder()
    if emb is None or _TECH_VEC is not None:
        return
    ttxt = [f"{t[1]}. {t[3]}" for t in TECH]
    _TYPE_KEYS = list(ATTACK_TYPE_DESC)
    _TECH_VEC = np.asarray(emb.encode(ttxt, normalize_embeddings=True, batch_size=64))
    _TYPE_VEC = np.asarray(emb.encode(list(ATTACK_TYPE_DESC.values()), normalize_embeddings=True, batch_size=32))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _join(items):
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def _cut(t, n=420):
    return t if len(t) <= n else t[:n - 1].rstrip() + "\u2026"


def _num(s):
    return float(s.replace(",", ""))


def _fmt(v):
    return f"{v:,.0f}" if abs(v - round(v)) < 1e-9 or v >= 100 else f"{v:,.2f}"


def refang(t):
    t = re.sub(r"\[\s*://\s*\]", "://", t)
    t = re.sub(r"\bhxxp(s?)", r"http\1", t, flags=re.I)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    return re.sub(r"\s?(?:\[at\]|\(at\)|\{at\}|\[@\])\s?", "@", t, flags=re.I)


def defang(v, typ):
    if typ == "URL":
        return re.sub(r"^http", "hxxp", v, flags=re.I).replace(".", "[.]")
    if typ == "Email address":
        return v.replace("@", "[at]").replace(".", "[.]")
    if typ in ("Domain", "IPv4 address"):
        return v.replace(".", "[.]")
    return v


def _ok_domain(d):
    d = (d or "").lower().rstrip(".")
    return d and not any(d == e or d.endswith("." + e) for e in EXAMPLE_DOMAINS)


def _ok_name(name):
    n = (name or "").strip(" .,;:|-")
    if len(n) < 3 or n.lower() in NAME_STOP:
        return False
    if n.lower() in ("windows", "linux", "macos", "android", "ios"):
        return False
    if FOOTER.search(n) or re.search(r"page \d", n, re.I):
        return False
    return True


def _split_names(blob):
    parts = re.split(r"\s*,\s*|\s+and\s+|\s+or\s+", blob.strip())
    return [p.strip() for p in parts if _ok_name(p)]


def certainty(text):
    if HEDGE.search(text):
        return "Suspected"
    if CONFIRM.search(text):
        return "Confirmed"
    return "Unclear"


def _is_rec(text):
    return bool((REC_MODAL.search(text) and REC_ACTION.search(text)) or REC_IMPERATIVE.match(text))


def _is_noise_sent(s):
    t = s["text"]
    return bool(FOOTER.search(t) or BOILER.search(t))


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------
def extract_pages(pdf_bytes):
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
            text_content = "\n".join([b[4] for b in blocks if b[6] == 0])
            
            try:
                for img in p.get_images():
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image = Image.open(io.BytesIO(image_bytes))
                    text_content += "\n" + pytesseract.image_to_string(image)
            except Exception:
                pass
            
            pages.append((i + 1, text_content))
            
        blob = "".join(t for _, t in pages)
        if not blob.strip():
            raise ValueError("This PDF is empty: no text could be found.")
        return pages
    finally:
        doc.close()


def _reflow(text):
    """Join wrapped PDF lines so URLs and sentences stay whole."""
    out, brk = [], True
    for ln in (l.strip() for l in text.splitlines()):
        if not ln:
            brk = True
            continue
        bullet = re.match(r"^([\u2022\-\*\u2013\u25aa\u25cf]|\d+[\.\)])\s", ln)
        if out and not brk and not bullet:
            prev = out[-1]
            glue = (not prev.endswith((".", "!", "?", ";", ":"))
                    or prev.endswith(("://", "/", "-", "=", "[.]", "[:]", ",")))
            if glue:
                out[-1] += "" if prev.endswith(("/", "-", "://")) else " "
                out[-1] += ln
            else:
                out.append(ln)
        else:
            out.append(ln)
        brk = False
    return out


def _page_text(text):
    return " ".join(_reflow(text))


# --------------------------------------------------------------------------
# Sentences
# --------------------------------------------------------------------------
def build_sentences(pages):
    pairs = [(_page_text(text), pno) for pno, text in pages]
    sents = []
    for doc, pno in _NLP.pipe(pairs, as_tuples=True, batch_size=8):
        for s in doc.sents:
            t = re.sub(r"\s+", " ", s.text).strip()
            if len(t) < 15 or len(t.split()) < 3:
                continue
            sents.append({
                "page": pno, "text": t, "lower": t.lower(),
                "lemma": " ".join(tok.lemma_.lower() for tok in s if tok.is_alpha),
                "orgs": [e.text.strip() for e in s.ents if e.label_ == "ORG"],
                "rec": _is_rec(t),
            })
    return sents


# --------------------------------------------------------------------------
# IOCs — page-level (avoids sentence-split URL fragments)
# --------------------------------------------------------------------------
def _cite(by_page, page, value, fallback_text):
    needle = refang(value).lower()
    for s in by_page.get(page, ()):
        if needle and needle in refang(s["text"]).lower():
            return s
    if by_page.get(page):
        return by_page[page][0]
    return {"page": page, "text": fallback_text}


def extract_iocs(pages, sents):
    by_page = OrderedDict()
    for s in sents:
        by_page.setdefault(s["page"], []).append(s)
    page_blob = {pno: _page_text(text) for pno, text in pages}
    ioc_pages = {pno for pno, t in page_blob.items() if IOC_SECTION.search(t)}
    found = OrderedDict()

    def add(typ, val, note, page, raw):
        val = val.rstrip(".,;:!?")
        k = (typ, val)
        if k in found:
            found[k]["count"] += 1
            return
        src = _cite(by_page, page, val, raw)
        found[k] = {"type": typ, "value": val, "note": note, "count": 1,
                    "page": src["page"], "sentence": src["text"]}

    def keep_net(page, raw_sent, value, typ):
        # Whole-page text always contains TLP/page footers; do not treat that as a reason to drop IOCs.
        if page in ioc_pages:
            return True
        if "[.]" in raw_sent or "hxxp" in raw_sent.lower() or "[at]" in raw_sent.lower() or "[:]" in raw_sent:
            return True
        if typ == "URL" and PAYLOAD_URL.search(value):
            return True
        if typ in ("URL", "Domain", "Email address"):
            host = (urlparse(value).hostname if typ == "URL" else value.split("@")[-1]).lower()
            if host.endswith(".gov") or host.endswith(".edu") or host.endswith(".mil"):
                return False
            return False
        if typ == "IPv4 address":
            return bool(re.search(r"\b(ip address|c2|command[- ]and[- ]control|payload|malicious|indicator)\b",
                                  raw_sent, re.I))
        return True

    for pno, raw in page_blob.items():
        t = refang(raw)
        for u in RE_URL.findall(t):
            u = u.rstrip(".,;:!?")
            host = (urlparse(u).hostname or "")
            if not _ok_domain(host or "x.invalid"):
                continue
            if keep_net(pno, raw, u, "URL"):
                add("URL", u, "", pno, raw)
                if host and RE_DOMAIN.fullmatch(host):
                    add("Domain", host.lower(), "host of a listed URL", pno, raw)
        t_wo = RE_URL.sub(" ", t)
        for e in RE_EMAIL.findall(t_wo):
            if _ok_domain(e.split("@")[1]) and keep_net(pno, raw, e, "Email address"):
                add("Email address", e.lower(), "", pno, raw)
        t_wo = RE_EMAIL.sub(" ", t_wo)
        for h in RE_HASH.findall(t_wo):
            add({32: "MD5 hash", 40: "SHA1 hash", 64: "SHA256 hash"}[len(h)], h.lower(), "", pno, raw)
        t_wo = RE_HASH.sub(" ", t_wo)
        for c in RE_CVE.findall(t_wo):
            add("CVE", c.upper(), "", pno, raw)
        t_wo = RE_CVE.sub(" ", t_wo)
        for m in RE_IPV6.findall(t_wo):
            try:
                ip = ipaddress.ip_address(m)
            except ValueError:
                continue
            if any(ip in n for n in DOC_NETS if n.version == 6) or ip.is_multicast or ip.is_unspecified:
                continue
            add("IPv6 address", str(ip),
                "private / internal address" if ip.is_private or ip.is_link_local else "", pno, raw)
        for m in RE_IPV4.findall(t_wo):
            try:
                ip = ipaddress.ip_address(m)
            except ValueError:
                continue
            if any(ip in n for n in DOC_NETS if n.version == 4) or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                continue
            if keep_net(pno, raw, m, "IPv4 address"):
                add("IPv4 address", str(ip),
                    "private / internal address" if ip.is_private or ip.is_loopback or ip.is_link_local else "",
                    pno, raw)
        t_wo = RE_IPV4.sub(" ", t_wo)
        
        for w in RE_BTC.findall(t_wo):
            add("Bitcoin address", w, "", pno, raw)
        for w in RE_XMR.findall(t_wo):
            add("Monero address", w, "", pno, raw)
        for w in RE_REGISTRY.findall(t_wo):
            add("Registry Key", w, "", pno, raw)
        for w in RE_FILEPATH_WIN.findall(t_wo):
            add("File Path (Windows)", w, "", pno, raw)
        for w in RE_FILEPATH_LINUX.findall(t_wo):
            if len(w) > 6 and not re.match(r"^\/\d{4}\/\d{2}", w):
                add("File Path (Linux)", w, "", pno, raw)
                
        if pno in ioc_pages:
            for d in (m.group(0) for m in RE_DOMAIN.finditer(t_wo)):
                if _ok_domain(d) and keep_net(pno, raw, d, "Domain"):
                    add("Domain", d.lower(), "", pno, raw)
    return list(found.values())


# --------------------------------------------------------------------------
# Actors / malware from context (no per-family gazetteer)
# --------------------------------------------------------------------------
def extract_actors(sents):
    names, statements = OrderedDict(), []

    def add_name(name, typ, label, s):
        name = re.sub(r"\s+", " ", name).strip(" .,;:")
        if not _ok_name(name):
            return
        if name in names:
            names[name]["count"] += 1
        else:
            names[name] = {"name": name, "type": typ, "label": label, "count": 1,
                           "page": s["page"], "sentence": s["text"]}

    for s in sents:
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
                
        for m in RE_SWID.finditer(t):
            add_name(m.group(1), "Malware / tool", "MALWARE", s)
        for m in RE_RANSOM_NAME.finditer(t):
            add_name(m.group(1), "Ransomware family", "RANSOMWARE", s)
        for m in RE_MALWARE_KIND.finditer(t):
            add_name(m.group(1), "Malware / tool", "MALWARE", s)
        for m in RE_APT.finditer(t):
            add_name(re.sub(r"\s+", "", m.group(0)).upper(), "Threat actor", "THREAT_ACTOR", s)
        for m in RE_AKA.finditer(t):
            for n in _split_names(m.group(1)):
                add_name(n, "Ransomware family", "RANSOMWARE", s)
        for m in RE_SUCH_AS.finditer(t):
            lab = "RANSOMWARE" if re.search(r"variant|ransom|famil", t, re.I) else "THREAT_ACTOR"
            typ = "Ransomware family" if lab == "RANSOMWARE" else "Threat actor"
            for n in _split_names(m.group(1)):
                add_name(n, typ, lab, s)
        for m in RE_GROUP_NAMED.finditer(t):
            add_name(m.group(1).split(",")[0], "Threat actor", "THREAT_ACTOR", s)

        hit = [n["name"] for n in names.values()
               if n["label"] in ("THREAT_ACTOR", "RANSOMWARE") and n["name"].lower() in s["lower"]]
        if hit and (ATTR_CUE.search(t) or CONFIRM.search(t) or re.search(r"\battribut", t, re.I)):
            statements.append({"actor": _join(dict.fromkeys(hit[:4])),
                               "certainty": certainty(t), "page": s["page"], "sentence": t})
        elif ATTR_CUE.search(t) and re.search(r"\b(actor|group|attacker|adversar|operator|gang)\b", t, re.I) and not hit:
            statements.append({"actor": "Unnamed actor", "certainty": certainty(t),
                               "page": s["page"], "sentence": t})
    return list(names.values()), statements


# --------------------------------------------------------------------------
# Attack types (cached type embeddings) + vectors from ATT&CK + language
# --------------------------------------------------------------------------
def attack_types(sents, sent_vecs, cand_idx):
    texts = [s["lemma"] for s in sents if not _is_noise_sent(s)]
    if not texts:
        return []
    if sent_vecs is not None and cand_idx and _TYPE_VEC is not None:
        sims = sent_vecs @ _TYPE_VEC.T  # (C, types)
        col = sims.max(axis=0)
        scores = {k: float(col[i]) for i, k in enumerate(_TYPE_KEYS)}
        best_row = sims.argmax(axis=0)
        total = sum(max(v, 0) for v in scores.values()) or 1.0
        out = []
        for i, k in enumerate(_TYPE_KEYS):
            sc = scores[k]
            if sc < 0.35 or sc / total < 0.07:
                continue
            src = sents[cand_idx[int(best_row[i])]]
            out.append({"type": k, "pct": round(100 * max(sc, 0) / total, 1),
                        "page": src["page"], "sentence": src["text"]})
        out.sort(key=lambda x: -x["pct"])
        ssum = sum(x["pct"] for x in out) or 1
        for x in out:
            x["pct"] = round(100 * x["pct"] / ssum, 1)
        return out[:5]
    vocab = sorted({w for ws in ATTACK_TYPE_DESC.values() for w in ws.split()})
    vec = TfidfVectorizer(vocabulary=vocab, ngram_range=(1, 3), sublinear_tf=True)
    X = vec.fit_transform(texts).tocsc()
    col = np.asarray(X.sum(axis=0)).ravel()
    scores = {}
    for t, desc in ATTACK_TYPE_DESC.items():
        scores[t] = float(sum(col[vec.vocabulary_[w]] for w in desc.split() if w in vec.vocabulary_))
    total = sum(scores.values()) or 1
    out = []
    usable = [s for s in sents if not _is_noise_sent(s)]
    for t, sc in sorted(scores.items(), key=lambda kv: -kv[1]):
        if sc <= 0 or sc / total < 0.07:
            continue
        idx = [vec.vocabulary_[w] for w in ATTACK_TYPE_DESC[t].split() if w in vec.vocabulary_]
        row = np.asarray(X[:, idx].sum(axis=1)).ravel()
        src = usable[int(row.argmax())]
        out.append({"type": t, "pct": round(100 * sc / total, 1), "page": src["page"], "sentence": src["text"]})
    return out[:5]


def attack_vectors(sents, mitre):
    seen, out = OrderedDict(), []
    for m in mitre:
        lab = TECH_TO_VECTOR.get(m["id"])
        if lab and lab not in seen:
            seen[lab] = m
            out.append({"vector": lab, "page": m["page"], "sentence": m["sentence"]})
    extras = [
        ("Phishing email", r"phish"),
        ("Exploitation of a vulnerability", r"\bcve-\d{4}-\d+|zero-?day|exploit\w*[^.]{0,40}vulnerabilit"),
        ("Stolen or weak credentials", r"password spray|brute[- ]force|compromised (?:credential|password)|valid accounts?"),
        ("Exposed remote access (RDP/VPN)", r"\brdp\b|remote desktop|\bssl-?vpn\b|\bvpn\b"),
        ("Supply chain / third party", r"supply[- ]chain|trojani[sz]ed"),
        ("Drive-by / malicious website", r"drive-by|watering hole"),
        ("Removable media", r"\busb\b|removable (?:media|drive)"),
        ("Misconfiguration / exposed service", r"misconfigur|publicly exposed"),
        ("Insider access", r"malicious insider|rogue employee"),
    ]
    for name, rx in extras:
        if name in seen:
            continue
        r = re.compile(rx, re.I)
        hit = next((s for s in sents if not s["rec"] and not _is_noise_sent(s) and r.search(s["text"])), None)
        if hit:
            out.append({"vector": name, "page": hit["page"], "sentence": hit["text"]})
    return out


def victim_assets(sents):
    out = []
    for name, rx in ASSET_RX:
        hits = [s for s in sents if not s["rec"] and not _is_noise_sent(s) and rx.search(s["text"])]
        if hits:
            out.append({"asset": name, "category": "System", "count": len(hits),
                        "page": hits[0]["page"], "sentence": hits[0]["text"]})
    orgs = OrderedDict()
    for s in sents:
        if s["rec"] or _is_noise_sent(s) or not VICTIM_CUE.search(s["text"]):
            continue
        for o in s["orgs"]:
            if _ok_name(o) and o not in orgs and len(o.split()) <= 6:
                orgs[o] = {"asset": o, "category": "Organisation named (spaCy NER)", "count": 1,
                           "page": s["page"], "sentence": s["text"]}
    return out + list(orgs.values())[:8]


# --------------------------------------------------------------------------
# MITRE — encode TTP-like sentences only; technique vectors cached
# --------------------------------------------------------------------------
def _candidates(sents):
    idx = []
    for i, s in enumerate(sents):
        if s["rec"] or _is_noise_sent(s) or len(s["text"].split()) < 5:
            continue
        if TTP_CUE.search(s["text"]) or RE_TECH_ID.search(s["text"]):
            idx.append(i)
    if len(idx) < 8:
        idx = [i for i, s in enumerate(sents)
               if not s["rec"] and not _is_noise_sent(s) and len(s["text"].split()) >= 8]
    return idx[:220]


def map_mitre(sents):
    cand_idx = _candidates(sents)
    if not cand_idx:
        return [], None, []
    stxt = [sents[i]["text"] for i in cand_idx]
    emb = _embedder()
    sent_vecs = None
    best = {}
    if emb is not None:
        _cache_vectors()
        sent_vecs = np.asarray(emb.encode(stxt, normalize_embeddings=True, batch_size=64))
        sims = sent_vecs @ _TECH_VEC.T
        thr = 0.48
        top2 = np.argpartition(-sims, 2, axis=1)[:, :2]
        for r, si in enumerate(cand_idx):
            s = sents[si]
            for j in top2[r]:
                sc = float(sims[r, j])
                if sc >= thr and (TECH[j][0] not in best or sc > best[TECH[j][0]][0]):
                    best[TECH[j][0]] = (sc, s)
    else:
        ttxt = [f"{t[1]}. {t[3]}" for t in TECH]
        tl = [" ".join(t.lemma_.lower() for t in d if t.is_alpha) for d in _NLP.pipe(ttxt)]
        v = TfidfVectorizer(stop_words="english", sublinear_tf=True).fit(tl + [sents[i]["lemma"] for i in cand_idx])
        sims = cosine_similarity(v.transform([sents[i]["lemma"] for i in cand_idx]), v.transform(tl))
        for r, si in enumerate(cand_idx):
            for j in np.argsort(-sims[r])[:2]:
                if sims[r][j] >= 0.22 and (TECH[j][0] not in best or sims[r][j] > best[TECH[j][0]][0]):
                    best[TECH[j][0]] = (float(sims[r][j]), sents[si])
    for s in sents:
        if _is_noise_sent(s):
            continue
        for m in RE_TECH_ID.finditer(s["text"]):
            tid = f"T{m.group(1)}"
            if tid in TECH_BY_ID:
                best[tid] = (1.0, s)
    rows = [{"id": k, "name": TECH_BY_ID[k][1], "tactic": TECH_BY_ID[k][2], "score": round(sc, 2),
             "page": s["page"], "sentence": s["text"]} for k, (sc, s) in best.items()]
    rows.sort(key=lambda r: (TACTIC_ORDER.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER else 99, r["id"]))
    return rows, sent_vecs, cand_idx


# --------------------------------------------------------------------------
# Timeline / impact / response
# --------------------------------------------------------------------------
def _parse_date(raw):
    raw = re.sub(r"(?<=\d)(st|nd|rd|th)\b", "", raw, flags=re.I)
    raw = re.sub(r"\bof\s+", "", raw, flags=re.I)
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        try:
            return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    d = dateparser.parse(raw, settings={"PREFER_DAY_OF_MONTH": "first", "DATE_ORDER": "DMY"})
    return d.date() if d else None


def extract_timeline(sents):
    events = []
    for s in sents:
        if FOOTER.search(s["text"]):
            continue
        for m in RE_DATE.finditer(s["text"]):
            d = _parse_date(m.group(0))
            if not d:
                continue
            marker = "Detection" if DETECT.search(s["text"]) else ("Compromise" if COMPROMISE.search(s["text"]) else "")
            events.append({"date": d, "precise": any(p.fullmatch(m.group(0)) for p in PRECISE), "marker": marker,
                           "page": s["page"], "sentence": s["text"]})
    events.sort(key=lambda e: (e["date"], e["page"]))
    seen, uniq = set(), []
    for e in events:
        k = (e["date"], e["sentence"])
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    events = uniq
    dwell = None
    comp = [e for e in events if e["marker"] == "Compromise"]
    if comp:
        first = comp[0]
        det = [e for e in events if e["marker"] == "Detection" and e["date"] >= first["date"]]
        if det:
            days = (det[0]["date"] - first["date"]).days
            dwell = {"days": days, "approx": not (first["precise"] and det[0]["precise"]),
                     "from": first["date"].strftime("%Y-%m-%d"), "to": det[0]["date"].strftime("%Y-%m-%d")}
    for e in events:
        e["label"] = e["date"].strftime("%Y-%m-%d") if e["precise"] else e["date"].strftime("%Y-%m") + " (month only)"
    return events, dwell


def extract_impact(sents):
    items, seen = [], set()

    def add(cat, raw, value, unit, s):
        k = (cat, raw.lower())
        if k not in seen:
            seen.add(k)
            items.append({"category": cat, "raw": raw, "value": value, "unit": unit,
                          "page": s["page"], "sentence": s["text"]})

    for s in sents:
        if s["rec"] or _is_noise_sent(s):
            continue
        t = s["text"]
        for m in RE_DATA.finditer(t):
            u = m.group(2).upper()[:2]
            gb = _num(m.group(1)) * {"PB": 1e6, "TB": 1e3, "GB": 1, "ME": 1e-3, "PE": 1e6, "TE": 1e3, "GI": 1}.get(u, 1)
            add("Data volume", m.group(0), gb, "GB", s)
        for m in RE_COUNT.finditer(t):
            val = _num(m.group(1)) * MULT.get((m.group(2) or "").lower(), 1)
            noun = m.group(3).lower()
            sysn = ("files", "devices", "systems", "endpoints", "servers", "machines")
            cat = "Systems / devices affected" if noun in sysn else "Records / users affected"
            if val >= 2 and not (1900 <= val <= 2100 and not m.group(2)):
                add(cat, m.group(0), val, noun, s)
        if DOWNTIME_CUE.search(t) and not re.search(r"undetected|dwell", t, re.I):
            for m in RE_DUR.finditer(t):
                unit = m.group(2).lower().rstrip("s")
                hrs = _num(m.group(1)) * {"minute": 1 / 60, "hour": 1, "day": 24, "week": 168}[unit]
                add("Downtime", m.group(0), hrs, "hours", s)
        for m in RE_MONEY1.finditer(t):
            mult = MULT.get((m.group(3) or m.group(4) or "").lower(), 1)
            add("Financial figure", m.group(0).strip(), _num(m.group(2)) * mult, CUR.get(m.group(1).lower(), "USD"), s)
        for m in RE_MONEY2.finditer(t):
            add("Financial figure", m.group(0).strip(), _num(m.group(1)) * MULT.get((m.group(2) or "").lower(), 1),
                CUR.get(m.group(3).lower(), "USD"), s)
    return items


def response_and_recs(sents):
    recs = [s for s in sents if s["rec"] and not RE_TECH_ID.search(s["text"]) and not _is_noise_sent(s)]
    resp = [s for s in sents if not s["rec"] and not _is_noise_sent(s)
            and RESP_VERB.search(s["text"]) and DEFENDER.search(s["text"]) and not ATTACKER.search(s["text"])]
    return resp, recs


def find_gaps(sents, R):
    g = []
    if not R["names"]:
        g.append("No threat actor, ransomware family or malware name is stated.")
    if not R["statements"]:
        g.append("No attribution statement is given.")
    elif not any(a["certainty"] != "Unclear" for a in R["statements"]):
        g.append("The confidence level of the attribution is not stated.")
    if not R["vectors"] and not any(i["type"] == "CVE" for i in R["iocs"]) and \
            not any(re.search(r"root cause|initial access|entry point|initial vector", s["text"], re.I) for s in sents):
        g.append("The root cause or initial access method is not stated.")
    if not R["events"]:
        g.append("No dated events are given, so no timeline can be built.")
    elif not R["dwell"]:
        g.append("Dwell time cannot be calculated because the dates of first compromise and detection are not both stated.")
    if not any(re.search(r"contain\w*|eradicat\w*|isolat\w*", s["text"], re.I) and not s["rec"]
               and (RE_DATE.search(s["text"]) or RE_DUR.search(s["text"])) for s in sents):
        g.append("The time taken to contain the incident is not stated.")
    cats = {i["category"] for i in R["impact"]}
    if not R["impact"]:
        g.append("The impact is not quantified (no data volumes, record counts, downtime or costs).")
    else:
        if "Financial figure" not in cats:
            g.append("No financial loss figure is stated.")
        if "Records / users affected" not in cats:
            g.append("The number of affected records or users is not stated.")
        if "Downtime" not in cats:
            g.append("The duration of downtime or service disruption is not stated.")
    if not R["iocs"]:
        g.append("No indicators of compromise are listed.")
    if not R["mitre"]:
        g.append("No attacker behaviour could be matched to a MITRE ATT&CK technique.")
    if not R["assets"]:
        g.append("The affected systems or assets are not identified.")
    if not R["resp"]:
        g.append("No response actions taken by the victim are described.")
    if not R["recs"]:
        g.append("The report gives no safety measures or recommendations.")
    return g


# --------------------------------------------------------------------------
# Charts + report template (same schema as the UI)
# --------------------------------------------------------------------------
IOC_GROUP = {"IPv4 address": "IP addresses", "IPv6 address": "IP addresses", "Domain": "Domains", "URL": "URLs",
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
}


def build_charts(R):
    charts = []
    grp = Counter()
    for i in R["iocs"]:
        g = IOC_GROUP.get(i["type"])
        if g:
            grp[g] += 1
    if len(grp) >= 2:
        tot = sum(grp.values())
        top, n = grp.most_common(1)[0]
        charts.append({"id": "ioc", "section": 4, "type": "doughnut", "title": "Indicators of compromise by type",
                       "labels": list(grp), "data": list(grp.values()),
                       "explanation": f"{top} make up {round(100 * n / tot)}% of all {tot} indicators, {IOC_MEANING[top]}."})
    tac = Counter(m["tactic"] for m in R["mitre"])
    if len(tac) >= 2:
        labs = [t for t in TACTIC_ORDER if t in tac]
        top, n = tac.most_common(1)[0]
        charts.append({"id": "tactics", "section": 6, "type": "bar", "title": "MITRE ATT&CK techniques per tactic",
                       "labels": labs, "data": [tac[t] for t in labs],
                       "explanation": f"The {len(R['mitre'])} mapped techniques span {len(tac)} tactics; {top} is the most represented "
                                      f"with {_plural(n, 'technique')}, showing where most of the described activity sits in the attack chain."})
    cert = Counter(a["certainty"] for a in R["statements"])
    if len(R["statements"]) >= 2 and len(cert) >= 2:
        top, n = cert.most_common(1)[0]
        charts.append({"id": "attribution", "section": 2, "type": "pie", "title": "Attribution certainty",
                       "labels": list(cert), "data": list(cert.values()),
                       "explanation": f"{n} of {len(R['statements'])} attribution statements are {top.lower()}, so the report's attribution "
                                      f"should be read as mostly {top.lower()} rather than settled."})
    imp = list(R["impact"])
    if len(imp) >= 2:
        big = max(imp, key=lambda i: i["value"])
        charts.append({"id": "impact", "section": 8, "type": "bar", "title": "Reported impact figures", "log": True,
                       "labels": [f"{i['category']}: {i['raw']}" for i in imp], "data": [i["value"] for i in imp],
                       "explanation": f"The report gives {len(imp)} numeric impact figures; the largest is {big['raw']}. Figures use different "
                                      "units (GB, hours, counts, currency), so they are drawn on a logarithmic scale for a rough comparison only."})
    per = Counter(e["label"] for e in R["events"])
    if len(R["events"]) >= 3 and len(per) >= 2:
        labs = list(OrderedDict.fromkeys(e["label"] for e in R["events"]))
        top, n = per.most_common(1)[0]
        span = (R["events"][-1]["date"] - R["events"][0]["date"]).days
        charts.append({"id": "timeline", "section": 7, "type": "line", "title": "Dated events over time",
                       "labels": labs, "data": [per[l] for l in labs],
                       "explanation": f"{len(R['events'])} dated events fall on {len(per)} distinct dates, spanning {_plural(span, 'day')}; "
                                      f"{top} is the busiest date with {_plural(n, 'event')}."})
    return charts


def executive_summary(R):
    p = []
    actors = [n["name"] for n in R["names"] if n["label"] in ("THREAT_ACTOR", "RANSOMWARE")]
    tools = [n["name"] for n in R["names"] if n["label"] == "MALWARE"]
    certs = {a["certainty"] for a in R["statements"]}
    if actors:
        who = _join(actors[:3])
        if "Suspected" in certs:
            p.append(f"The activity is suspected to be linked to {who}.")
        elif "Confirmed" in certs:
            p.append(f"The report attributes the activity to {who}.")
        else:
            p.append(f"The report mentions {who} but does not say how firmly the activity is attributed.")
    else:
        p.append("The report does not name a specific threat actor.")
    if tools:
        p.append(f"The malware or tools named include {_join(tools[:4])}.")
    if R["types"]:
        t = [x["type"] for x in R["types"]]
        p.append(f"The main attack type described is {t[0].lower()}" +
                 (f", with signs of {_join(x.lower() for x in t[1:3])}." if len(t) > 1 else "."))
    if R["vectors"]:
        v = [x["vector"] for x in R["vectors"][:3]]
        p.append(f"The report points to {_join(x[0].lower() + x[1:] for x in v)} as the way in.")
    ev = R["events"]
    if ev:
        d = sorted({e["label"] for e in ev})
        p.append(f"The report gives a single date, {d[0]}." if len(d) == 1 else
                 f"The earliest dated event is {ev[0]['label']} and the latest is {ev[-1]['label']}.")
    if R["dwell"]:
        w = R["dwell"]
        p.append(f"The attackers were present for {'about ' if w['approx'] else ''}{_plural(w['days'], 'day')} before detection.")
    if R["impact"]:
        p.append(f"Reported impact includes {_join([i['raw'] for i in R['impact'][:3]])}.")
    else:
        p.append("The report does not quantify the impact.")
    sysn = [a["asset"] for a in R["assets"] if a["category"] == "System"][:4]
    if sysn:
        p.append(f"Affected systems mentioned include {_join(x.lower() if not x.isupper() else x for x in sysn)}.")
    if R["resp"] or R["recs"]:
        p.append(f"The report describes {_plural(len(R['resp']), 'response action')} and states {_plural(len(R['recs']), 'recommendation')}.")
    else:
        p.append("The report describes no response actions or recommendations.")
    return " ".join(p)


def _sec(no, title, summary=None, tables=None):
    tables = [t for t in (tables or []) if t["rows"]]
    return {"no": no, "title": title, "summary": summary, "tables": tables, "empty": not tables and not summary}


def _tab(name, cols, rows):
    return {"name": name, "columns": cols, "rows": rows}


def _title(pages):
    for ln in pages[0][1].splitlines():
        t = ln.strip()
        if len(t) > 8 and not SKIP_TITLE.search(t) and not FOOTER.search(t):
            return t[:120]
    for ln in pages[0][1].splitlines():
        if len(ln.strip()) > 6:
            return ln.strip()[:120]
    return "Untitled incident report"


def analyze_pdf(pdf_bytes):
    pages = extract_pages(pdf_bytes)
    load_models()
    sents = build_sentences(pages)
    if not sents:
        raise ValueError("No readable sentences were found in this PDF.")
    R = {}
    R["iocs"] = extract_iocs(pages, sents)
    R["names"], R["statements"] = extract_actors(sents)
    R["mitre"], sent_vecs, cand_idx = map_mitre(sents)
    R["types"] = attack_types(sents, sent_vecs, cand_idx)
    R["vectors"] = attack_vectors(sents, R["mitre"])
    R["assets"] = victim_assets(sents)
    R["events"], R["dwell"] = extract_timeline(sents)
    R["impact"] = extract_impact(sents)
    R["resp"], R["recs"] = response_and_recs(sents)
    R["gaps"] = find_gaps(sents, R)
    charts = build_charts(R)

    ioc_tabs = []
    for typ in ("IPv4 address", "IPv6 address", "Domain", "URL", "MD5 hash", "SHA1 hash", "SHA256 hash",
                "Email address", "CVE", "Bitcoin address", "Monero address", "Registry Key", "File Path (Windows)", "File Path (Linux)"):
        rows = [[defang(i["value"], typ), i["note"] or "-", i["count"], i["page"], _cut(i["sentence"])]
                for i in R["iocs"] if i["type"] == typ]
        ioc_tabs.append(_tab(typ + ("es" if typ.endswith("ss") else "es" if typ.endswith("sh") else "s"),
                             ["Indicator (defanged)", "Note", "Mentions", "Page", "Source sentence"], rows))
    dw = R["dwell"]
    tl_sum = (f"Dwell time (first compromise to detection): {'about ' if dw['approx'] else ''}{_plural(dw['days'], 'day')} "
              f"({dw['from']} to {dw['to']})." if dw else None)
    cert_all = "Suspected" if "Suspected" in {a["certainty"] for a in R["statements"]} else \
        ("Confirmed" if "Confirmed" in {a["certainty"] for a in R["statements"]} else
         ("Unclear" if R["statements"] else None))
    sections = [
        _sec(1, "Executive Summary", executive_summary(R)),
        _sec(2, "Threat Actor and Attribution", f"Overall attribution certainty: {cert_all}." if cert_all else None, [
            _tab("Named threat actors, ransomware families and malware",
                 ["Name", "Type", "Mentions", "Page", "Source sentence"],
                 [[n["name"], n["type"], n["count"], n["page"], _cut(n["sentence"])] for n in R["names"]]),
            _tab("Attribution statements", ["Actor", "Certainty", "Page", "Source sentence"],
                 [[a["actor"], a["certainty"], a["page"], _cut(a["sentence"])] for a in R["statements"]])]),
        _sec(3, "Attack Type and Vector", None, [
            _tab("Attack types (score share)", ["Attack type", "Score %", "Page", "Source sentence"],
                 [[t["type"], t["pct"], t["page"], _cut(t["sentence"])] for t in R["types"]]),
            _tab("Attack vectors", ["Vector", "Page", "Source sentence"],
                 [[v["vector"], v["page"], _cut(v["sentence"])] for v in R["vectors"]])]),
        _sec(4, "Indicators of Compromise (IOCs)", f"{len(R['iocs'])} unique indicators found." if R["iocs"] else None,
             ioc_tabs),
        _sec(5, "Victim Assets and Affected Systems", None, [
            _tab("Affected assets", ["Asset / organisation", "Category", "Mentions", "Page", "Source sentence"],
                 [[a["asset"], a["category"], a["count"], a["page"], _cut(a["sentence"])] for a in R["assets"]])]),
        _sec(6, "MITRE ATT&CK Techniques", None, [
            _tab("Mapped techniques", ["ID", "Technique", "Tactic", "Match", "Page", "Source sentence"],
                 [[m["id"], m["name"], m["tactic"], m["score"], m["page"], _cut(m["sentence"])] for m in R["mitre"]])]),
        _sec(7, "Timeline of Events", tl_sum, [
            _tab("Dated events", ["Date", "Marker", "Page", "Event (source sentence)"],
                 [[e["label"], e["marker"] or "-", e["page"], _cut(e["sentence"])] for e in R["events"]])]),
        _sec(8, "Impact Assessment", None, [
            _tab("Impact figures", ["Category", "Figure (as written)", "Normalised", "Page", "Source sentence"],
                 [[i["category"], i["raw"], f"{_fmt(i['value'])} {i['unit']}", i["page"], _cut(i["sentence"])]
                  for i in R["impact"]])]),
        _sec(9, "Response Actions Taken", None, [
            _tab("Actions described in the report", ["Page", "Source sentence"],
                 [[s["page"], _cut(s["text"])] for s in R["resp"]])]),
        _sec(10, "Safety Measures and Recommendations", None, [
            _tab("Recommendations stated in the report", ["Page", "Source sentence"],
                 [[s["page"], _cut(s["text"])] for s in R["recs"]])]),
        _sec(11, "Gaps in the Report", None,
             [_tab("Information the report does not state", ["Missing information"], [[g] for g in R["gaps"]])]),
    ]
    actors = [n["name"] for n in R["names"] if n["label"] in ("THREAT_ACTOR", "RANSOMWARE")]
    report = {
        "title": _title(pages), "pages": len(pages), "sentences": len(sents),
        "layout": "dashboard" if len(charts) >= 3 else "inline",
        "key_points": {"Threat actor": _join(actors[:2]) or "Not stated",
                       "Attack type": R["types"][0]["type"] if R["types"] else "Not stated",
                       "Dwell time": (f"{dw['days']} days" if dw else "Not available"),
                       "IOCs found": len(R["iocs"]), "ATT&CK techniques": len(R["mitre"])},
        "sections": sections, "charts": charts,
    }
    return report, "\n\n".join(t for _, t in pages)
