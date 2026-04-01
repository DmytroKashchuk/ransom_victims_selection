"""
extract_domains_for_httparchive.py - Lista pulita di domini vittime per il join con HTTP Archive
Output: output/victim_domains_for_httparchive.csv
"""
import json, csv, re, glob, os
from collections import defaultdict

os.makedirs("output", exist_ok=True)

domains = defaultdict(lambda: {"sources": set(), "revenues": [], "dates": [], "group": set()})

# ============================================================
# CONTI - from chat victim reports
# ============================================================
if os.path.exists("conti-leaks-englished"):
    for f in sorted(glob.glob("conti-leaks-englished/english_chats/deepl_translated_jabber/**/*.json", recursive=True)):
        buf = ""
        for line in open(f):
            buf += line
            if line.strip() == "}":
                try:
                    m = json.loads(buf)
                except json.JSONDecodeError:
                    buf = ""
                    continue
                buf = ""
                body = m.get("body", "") or ""
                ts = m.get("ts", "")[:10]

                # Extract website from structured reports
                sites = re.findall(r'(?:site|website)[:\s]+(?:https?://)?(?:www\.)?([a-zA-Z0-9\-]+\.[a-zA-Z.]{2,})', body, re.I)
                if not sites:
                    sites = re.findall(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9\-]+\.(?:com|org|net|edu|gov|co\.\w+|com\.\w+))', body)

                rev = ""
                rev_match = re.search(r'(?:revenue|revenu)[:\s]*\$?([\d,.]+\s*(?:million|billion|M|B|kk)?)', body, re.I)
                if rev_match:
                    rev = rev_match.group(1)

                # Only include if it looks like a victim report
                if re.search(r'serv|comp|revenue|million|billion|employee|backup', body, re.I):
                    for s in sites:
                        d = s.lower().strip(".")
                        if len(d) > 4 and "." in d:
                            domains[d]["sources"].add("conti_chat")
                            domains[d]["group"].add("conti")
                            if rev: domains[d]["revenues"].append(rev)
                            if ts: domains[d]["dates"].append(ts)

# ============================================================
# BLACK BASTA - from Matrix chat ZoomInfo links
# ============================================================
if os.path.exists("BlackBasta-Chats"):
    with open("BlackBasta-Chats/blackbasta_chats.json") as f:
        raw = f.read()
    for b in raw.strip().split("\n}\n"):
        b = b.strip().strip("{").strip("}").strip()
        m = {}
        for line in b.split("\n"):
            line = line.strip().rstrip(",")
            if ":" in line:
                m[line.split(":")[0].strip()] = ":".join(line.split(":")[1:]).strip()

        body = m.get("message", "")
        ts = m.get("timestamp", "")[:10]

        # Extract domains from ZoomInfo-adjacent messages
        if "zoominfo" in body.lower() or re.search(r'\d+[kM]\s', body):
            sites = re.findall(r'([a-zA-Z0-9\-]+\.(?:com|org|net|co|local|be|nl|uk|de|fr|it|br|au|ca|ch|at|es|pl|se|dk|no|fi|jp|kr|tw|ph|sg|ae|sa|my|th|vn|id|in|mx|cl|pe|ar)(?:\.[a-z]{2})?)', body)
            for s in sites:
                d = s.lower()
                if d in ("zoominfo.com", "bleepingcomputer.com", "github.com"):
                    continue
                if len(d) > 4:
                    domains[d]["sources"].add("blackbasta_chat")
                    domains[d]["group"].add("blackbasta")
                    if ts: domains[d]["dates"].append(ts)

                    rev_match = re.search(r'([\d.]+)\s*(M|B|kk+|Million|Billion)', body, re.I)
                    if rev_match:
                        domains[d]["revenues"].append(rev_match.group(1) + rev_match.group(2))

# ============================================================
# LOCKBIT - from build configurations
# ============================================================
if os.path.exists("LockBit-Database-Leak-2025"):
    with open("LockBit-Database-Leak-2025/lockbit-builds-configurations.csv") as f:
        for r in csv.DictReader(f):
            config = json.loads(r["config"])
            bm = config.get("buildModel", {})
            website = (bm.get("company_website", config.get("company_website", "")) or "").lower().strip()
            revenue = bm.get("revenue", config.get("revenue", ""))
            build_date = bm.get("created_at", r.get("created_at", ""))[:10]

            if not website or len(website) < 5 or "." not in website:
                continue

            domains[website]["sources"].add("lockbit_build")
            domains[website]["group"].add("lockbit")
            if revenue: domains[website]["revenues"].append(revenue)
            if build_date: domains[website]["dates"].append(build_date)

# ============================================================
# FILTER AND CLEAN
# ============================================================
skip_patterns = [
    r"^example\.com$", r"^test", r"^qwe\.", r"^asd\.", r"^sad\.",
    r"^google\.com$", r"^microsoft\.com$", r"^yahoo\.",
    r"^\d+\.com$", r"^nosite\.", r"^noname\.", r"^justtotest\.",
    r"^fasddfs\.", r"^fdsfds\.", r"^ghshsgh\.", r"^qergqerg\.",
    r"^sdadsa\.", r"^black\.black$", r"^tsst\.", r"^tst\.",
    r"\.local$", r"\.onion$",
    r"^osamabinladen", r"^usvictims\.",
]

clean = []
for d, info in sorted(domains.items()):
    if any(re.search(p, d) for p in skip_patterns):
        continue
    if len(d) < 5:
        continue

    clean.append({
        "domain": d,
        "groups": ";".join(sorted(info["group"])),
        "sources": ";".join(sorted(info["sources"])),
        "revenue": info["revenues"][0] if info["revenues"] else "",
        "first_seen": min(info["dates"]) if info["dates"] else "",
        "last_seen": max(info["dates"]) if info["dates"] else "",
        "mention_count": len(info["dates"]),
    })

with open("output/victim_domains_for_httparchive.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["domain", "groups", "sources", "revenue", "first_seen", "last_seen", "mention_count"])
    w.writeheader()
    w.writerows(clean)

print(f"Extracted {len(clean)} unique victim domains -> output/victim_domains_for_httparchive.csv")
print(f"  Conti:      {sum(1 for c in clean if 'conti' in c['groups'])}")
print(f"  BlackBasta: {sum(1 for c in clean if 'blackbasta' in c['groups'])}")
print(f"  LockBit:    {sum(1 for c in clean if 'lockbit' in c['groups'])}")
print(f"  Multi-group:{sum(1 for c in clean if ';' in c['groups'])}")

# Quick stats
print("\nRevenue distribution:")
for c in clean[:10]:
    print(f"  {c['domain']:<40s} {c['groups']:<20s} rev={c['revenue']}")
