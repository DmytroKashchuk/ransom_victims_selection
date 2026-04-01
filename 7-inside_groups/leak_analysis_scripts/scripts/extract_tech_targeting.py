"""
extract_tech_targeting.py - Estrae keyword tecnologiche, CVE e tool di recon da tutti i leak
Output: output/tech_keywords.csv, output/cves_mentioned.csv, output/recon_tools.csv, output/domains_mentioned.csv
"""
import json, csv, re, glob, os
from collections import Counter, defaultdict

os.makedirs("output", exist_ok=True)

TECH_PATTERNS = {
    # Network appliances / initial access
    "sonicwall": r"\bsonicwall\b", "citrix": r"\bcitrix\b",
    "fortinet": r"\bfortinet\b", "fortigate": r"\bfortigate\b",
    "palo_alto": r"\bpalo\s*alto\b", "cisco": r"\bcisco\b",
    "juniper": r"\bjuniper\b", "pulse_secure": r"\bpulse\s*secure\b",
    # Remote access
    "vpn": r"\bvpn\b", "rdp": r"\brdp\b", "anydesk": r"\banydesk\b",
    "teamviewer": r"\bteamviewer\b",
    # Web / CMS
    "wordpress": r"\bwordpress\b", "drupal": r"\bdrupal\b", "joomla": r"\bjoomla\b",
    "php": r"\bphp\b", "apache": r"\bapache\b", "nginx": r"\bnginx\b", "iis": r"\biis\b",
    # Enterprise infra
    "exchange": r"\bexchange\b", "sharepoint": r"\bsharepoint\b",
    "esxi": r"\besxi\b", "vmware": r"\bvmware\b", "veeam": r"\bveeam\b",
    "hyper_v": r"\bhyper[\s-]?v\b", "sql_server": r"\bsql\s*server\b",
    # Security products
    "defender": r"\bdefender\b", "sophos": r"\bsophos\b", "crowdstrike": r"\bcrowdstrike\b",
    "sentinelone": r"\bsentinel\s*one\b", "carbonblack": r"\bcarbon\s*black\b",
    "kaspersky": r"\bkaspersky\b", "eset": r"\beset\b",
    # Recon / OSINT tools
    "zoominfo": r"\bzoominfo\b", "shodan": r"\bshodan\b", "censys": r"\bcensys\b",
    "fofa": r"\bfofa\b", "spiderfoot": r"\bspiderfoot\b", "masscan": r"\bmasscan\b",
    "nmap": r"\bnmap\b", "crunchbase": r"\bcrunchbase\b",
    "signalhire": r"\bsignalhire\b", "rocketreach": r"\brocketreach\b",
    # Offensive tools
    "cobalt_strike": r"\bcobalt\s*strike\b", "metasploit": r"\bmetasploit\b",
    "mimikatz": r"\bmimikatz\b", "powershell": r"\bpowershell\b",
    "rclone": r"\brclone\b",
    # AI
    "chatgpt": r"\bchatgpt\b", "wormgpt": r"\bwormgpt\b",
    # Targeting terms
    "revenue": r"\brevenue\b", "insurance": r"\binsurance\b",
    "hospital": r"\bhospital\b", "government": r"\bgovernment\b",
    "backup": r"\bbackup\b",
}

CVE_PATTERN = re.compile(r"CVE[-\s]?\d{4}[-\s]?\d{4,}", re.I)
URL_PATTERN = re.compile(r"https?://([^\s<>\"'\\]+)")

def load_conti(base_path):
    msgs = []
    for f in sorted(glob.glob(f"{base_path}/english_chats/deepl_translated_jabber/**/*.json", recursive=True)):
        buf = ""
        for line in open(f):
            buf += line
            if line.strip() == "}":
                try:
                    obj = json.loads(buf)
                except json.JSONDecodeError:
                    buf = ""
                    continue
                obj["_src"] = "conti"
                msgs.append(obj)
                buf = ""
    return msgs

def load_blackbasta(base_path):
    with open(f"{base_path}/blackbasta_chats.json") as f:
        raw = f.read()
    msgs = []
    for b in raw.strip().split("\n}\n"):
        b = b.strip().strip("{").strip("}").strip()
        m = {}
        for line in b.split("\n"):
            line = line.strip().rstrip(",")
            if ":" in line:
                key = line.split(":")[0].strip()
                val = ":".join(line.split(":")[1:]).strip()
                m[key] = val
        if m:
            m["_src"] = "blackbasta"
            msgs.append(m)
    return msgs

def get_body(m):
    return m.get("body", m.get("message", m.get("text", ""))) or ""

def get_sender(m):
    if "from" in m:
        return m["from"].split("@")[0]
    if "sender_alias" in m:
        return m["sender_alias"].split(":")[0].replace("@", "")
    return ""

def get_ts(m):
    return (m.get("ts", m.get("timestamp", "")))[:10]

# ============================================================
# LOAD ALL MESSAGES
# ============================================================
all_msgs = []
print("Loading Conti...")
if os.path.exists("conti-leaks-englished"):
    all_msgs.extend(load_conti("conti-leaks-englished"))
print(f"  {sum(1 for m in all_msgs if m.get('_src')=='conti')} msgs")

print("Loading Black Basta...")
if os.path.exists("BlackBasta-Chats"):
    all_msgs.extend(load_blackbasta("BlackBasta-Chats"))
print(f"  {sum(1 for m in all_msgs if m.get('_src')=='blackbasta')} msgs")

print(f"Total: {len(all_msgs)} messages\n")

# ============================================================
# 1. TECH KEYWORDS
# ============================================================
print("Extracting tech keywords...")
tech_rows = []
for m in all_msgs:
    body = get_body(m).lower()
    for kw, pat in TECH_PATTERNS.items():
        if re.search(pat, body):
            tech_rows.append({
                "source": m.get("_src"),
                "date": get_ts(m),
                "sender": get_sender(m),
                "keyword": kw,
                "snippet": get_body(m)[:300].replace("\n", " ")
            })

with open("output/tech_keywords.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["source", "date", "sender", "keyword", "snippet"])
    w.writeheader()
    w.writerows(tech_rows)

# Summary
kw_counts = Counter((r["source"], r["keyword"]) for r in tech_rows)
print(f"  {len(tech_rows)} keyword hits -> output/tech_keywords.csv")
print("  Top 15 by source:")
for (src, kw), cnt in kw_counts.most_common(15):
    print(f"    {src:12s} {kw:20s} {cnt:5d}")

# ============================================================
# 2. CVEs MENTIONED
# ============================================================
print("\nExtracting CVEs...")
cve_rows = []
for m in all_msgs:
    body = get_body(m)
    cves = CVE_PATTERN.findall(body)
    for c in cves:
        cve_rows.append({
            "source": m.get("_src"),
            "date": get_ts(m),
            "sender": get_sender(m),
            "cve": c.upper().replace(" ", "-"),
            "snippet": body[:300].replace("\n", " ")
        })

with open("output/cves_mentioned.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["source", "date", "sender", "cve", "snippet"])
    w.writeheader()
    w.writerows(cve_rows)

cve_counts = Counter(r["cve"] for r in cve_rows)
print(f"  {len(cve_rows)} CVE mentions -> output/cves_mentioned.csv")
print("  Top 15:")
for cve, cnt in cve_counts.most_common(15):
    print(f"    {cve:20s} {cnt:5d}")

# ============================================================
# 3. DOMAINS MENTIONED (potential victim sites)
# ============================================================
print("\nExtracting domains from URLs...")
domain_counts = defaultdict(lambda: Counter())
for m in all_msgs:
    body = get_body(m)
    urls = URL_PATTERN.findall(body)
    src = m.get("_src", "")
    for u in urls:
        domain = u.split("/")[0].split(":")[0].lower()
        domain_counts[src][domain] += 1

with open("output/domains_mentioned.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["source", "domain", "count"])
    for src in sorted(domain_counts):
        for dom, cnt in domain_counts[src].most_common():
            w.writerow([src, dom, cnt])

total_doms = sum(len(v) for v in domain_counts.values())
print(f"  {total_doms} unique domains -> output/domains_mentioned.csv")

# ============================================================
# 4. RECON TOOL USAGE SUMMARY
# ============================================================
print("\nRecon tools summary...")
recon_tools = ["zoominfo", "shodan", "censys", "fofa", "spiderfoot",
               "masscan", "nmap", "crunchbase", "signalhire", "rocketreach"]
recon_rows = []
for r in tech_rows:
    if r["keyword"] in recon_tools:
        recon_rows.append(r)

with open("output/recon_tools.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["source", "date", "sender", "keyword", "snippet"])
    w.writeheader()
    w.writerows(recon_rows)

recon_summary = Counter((r["source"], r["keyword"]) for r in recon_rows)
print(f"  {len(recon_rows)} recon tool mentions -> output/recon_tools.csv")
for (src, tool), cnt in sorted(recon_summary.items(), key=lambda x: (-x[1], x[0])):
    print(f"    {src:12s} {tool:15s} {cnt:5d}")

print("\nDone!")
