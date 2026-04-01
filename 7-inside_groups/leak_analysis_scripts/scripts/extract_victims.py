"""
extract_victims.py - Estrae profili vittime da Conti, Black Basta e LockBit leaks
Output: output/victims_unified.csv
"""
import json, csv, re, glob, os

OUTPUT = "output/victims_unified.csv"
victims = []

# ============================================================
# CONTI - victim reports from Jabber chats
# ============================================================
def parse_conti(base_path):
    msgs = []
    for f in sorted(glob.glob(f"{base_path}/english_chats/deepl_translated_jabber/**/*.json", recursive=True)):
        buf = ""
        for line in open(f):
            buf += line
            if line.strip() == "}":
                try:
                    obj = json.loads(buf)
                    msgs.append(obj)
                except json.JSONDecodeError:
                    pass
                buf = ""

    for m in msgs:
        body = m.get("body", "") or ""
        sender = m.get("from", "").split("@")[0]
        ts = m.get("ts", "")[:10]

        # Pattern: ZoomInfo + server/revenue reports
        if "zoominfo.com" not in body.lower():
            continue

        # Extract domain
        site = ""
        site_match = re.search(r'(?:site|website)[:\s]+(?:https?://)?(?:www\.)?([a-zA-Z0-9\-]+\.[a-zA-Z.]{2,})', body, re.I)
        if site_match:
            site = site_match.group(1).lower()

        # Extract revenue
        rev = ""
        rev_match = re.search(r'(?:revenue|revenu)[:\s]*\$?([\d,.]+\s*(?:million|billion|M|B|kk|kkk)?)', body, re.I)
        if rev_match:
            rev = rev_match.group(1).strip()

        # Extract server/computer counts
        servers = ""
        srv_match = re.search(r'(\d+)\s*serv', body, re.I)
        if srv_match:
            servers = srv_match.group(1)

        comps = ""
        comp_match = re.search(r'(\d+)\s*comp', body, re.I)
        if comp_match:
            comps = comp_match.group(1)

        # Extract ZoomInfo URL for company ID
        zoom_url = ""
        zoom_match = re.search(r'(https?://www\.zoominfo\.com/c/[^\s\\]+)', body)
        if zoom_match:
            zoom_url = zoom_match.group(1)

        victims.append({
            "source": "conti",
            "date": ts,
            "sender": sender,
            "domain": site,
            "revenue": rev,
            "servers": servers,
            "computers": comps,
            "zoominfo_url": zoom_url,
            "sector": "",
            "country": "",
            "cves_mentioned": "",
            "raw_snippet": body[:500].replace("\n", " ")
        })

# ============================================================
# BLACK BASTA - victim reports from Matrix chats
# ============================================================
def parse_blackbasta(base_path):
    with open(f"{base_path}/blackbasta_chats.json") as f:
        raw = f.read()

    blocks = raw.strip().split("\n}\n")
    for b in blocks:
        b = b.strip().strip("{").strip("}").strip()
        m = {}
        for line in b.split("\n"):
            line = line.strip().rstrip(",")
            if ":" in line:
                key = line.split(":")[0].strip()
                val = ":".join(line.split(":")[1:]).strip()
                m[key] = val
        if not m:
            continue

        body = m.get("message", "")
        if "zoominfo.com" not in body.lower():
            continue

        sender = m.get("sender_alias", "").split(":")[0].replace("@", "")
        ts = m.get("timestamp", "")[:10]

        # Extract domain from message
        site = ""
        site_match = re.search(r'(?:DOMAIN/?|domain/?\s*)\s*([a-zA-Z0-9\-]+\.[a-zA-Z.]{2,})', body)
        if not site_match:
            site_match = re.search(r'([a-zA-Z0-9\-]+\.(?:com|org|net|co|local|be|nl|uk))', body)
        if site_match:
            site = site_match.group(1).lower()

        # Extract revenue - BB uses format like "252M", "3.6B", "1kkk"
        rev = ""
        rev_match = re.search(r'([\d.]+)\s*(M|B|kk+|Million|Billion)', body, re.I)
        if rev_match:
            rev = rev_match.group(1) + rev_match.group(2)

        zoom_url = ""
        zoom_match = re.search(r'(https?://www\.zoominfo\.com/c/[^\s\\]+)', body)
        if zoom_match:
            zoom_url = zoom_match.group(1)

        # Extract country
        country = ""
        country_match = re.search(r'\b(USA|US|UK|DE|FR|IT|CA|AU|BR|IN|NL|BE|CH)\b', body)
        if country_match:
            country = country_match.group(1)

        victims.append({
            "source": "blackbasta",
            "date": ts,
            "sender": sender,
            "domain": site,
            "revenue": rev,
            "servers": "",
            "computers": "",
            "zoominfo_url": zoom_url,
            "sector": "",
            "country": country,
            "cves_mentioned": "",
            "raw_snippet": body[:500].replace("\n", " ")
        })

# ============================================================
# LOCKBIT - victim data from SQL dump
# ============================================================
def parse_lockbit(base_path):
    with open(f"{base_path}/lockbit-builds-configurations.csv") as f:
        rows = list(csv.DictReader(f))

    skip = {'example.com','qwe.com','tstchat.com','testbyosama.com','test.com',
            'google.com','microsoft.com','yahoo.fr','asda.com'}

    for r in rows:
        config = json.loads(r["config"])
        bm = config.get("buildModel", {})
        website = bm.get("company_website", config.get("company_website", ""))
        revenue = bm.get("revenue", config.get("revenue", ""))
        build_date = bm.get("created_at", r.get("created_at", ""))[:10]

        if not website or website in skip:
            continue
        if re.match(r'^\d+\.com$', website):
            continue

        # Extract custom kill lists (non-default additions)
        kill_svc = config.get("kill_services_list", "")
        kill_proc = config.get("kill_processes_list", "")

        # Detect custom tech additions beyond default template
        default_svcs = "vss;sql;svc$;memtas;mepocs;msexchange;sophos;veeam;backup;GxVss;GxBlr;GxFWD;GxCVD;GxCIMgr"
        custom_svcs = ""
        if kill_svc and kill_svc != default_svcs:
            extra = set(kill_svc.split(";")) - set(default_svcs.split(";"))
            custom_svcs = ";".join(extra) if extra else ""

        victims.append({
            "source": "lockbit",
            "date": build_date,
            "sender": f"affiliate_{bm.get('userid', 'unknown')}",
            "domain": website.lower().strip(),
            "revenue": revenue,
            "servers": "",
            "computers": "",
            "zoominfo_url": "",
            "sector": "",
            "country": "",
            "cves_mentioned": "",
            "raw_snippet": f"build_type={r.get('build_type','')} custom_services={custom_svcs}"
        })

# ============================================================
# MAIN
# ============================================================
print("Parsing Conti leaks...")
if os.path.exists("conti-leaks-englished"):
    parse_conti("conti-leaks-englished")
print(f"  -> {sum(1 for v in victims if v['source']=='conti')} victim records")

print("Parsing Black Basta leaks...")
if os.path.exists("BlackBasta-Chats"):
    parse_blackbasta("BlackBasta-Chats")
print(f"  -> {sum(1 for v in victims if v['source']=='blackbasta')} victim records")

print("Parsing LockBit leaks...")
if os.path.exists("LockBit-Database-Leak-2025"):
    parse_lockbit("LockBit-Database-Leak-2025")
print(f"  -> {sum(1 for v in victims if v['source']=='lockbit')} victim records")

os.makedirs("output", exist_ok=True)
if victims:
    with open(OUTPUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(victims[0].keys()))
        w.writeheader()
        w.writerows(victims)
    print(f"\nTotal: {len(victims)} victim records -> {OUTPUT}")
else:
    print("No victims found!")
