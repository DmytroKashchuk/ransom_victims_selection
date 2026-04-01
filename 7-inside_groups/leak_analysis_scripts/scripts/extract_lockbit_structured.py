"""
extract_lockbit_structured.py - Estrae dati strutturati dal dump SQL di LockBit
Output: output/lockbit_builds_clean.csv, output/lockbit_affiliates.csv, output/lockbit_negotiations.csv
"""
import csv, json, re, os
from datetime import datetime

os.makedirs("output", exist_ok=True)
BASE = "LockBit-Database-Leak-2025"

# ============================================================
# 1. BUILDS - ogni build = un attacco pianificato
# ============================================================
print("Parsing builds + configurations...")
configs = {}
with open(f"{BASE}/lockbit-builds-configurations.csv") as f:
    for r in csv.DictReader(f):
        config = json.loads(r["config"])
        configs[r["build_id"]] = {
            "build_type": r["build_type"],
            "kill_services": config.get("kill_services_list", ""),
            "kill_processes": config.get("kill_processes_list", ""),
            "white_folders": config.get("white_folders", ""),
            "white_extensions": config.get("white_extens", ""),
            "spread_enabled": config.get("spread_enabled", ""),
            "kill_defender": config.get("kill_defender", ""),
            "language_check": config.get("language_check", ""),  # CIS country check
            "encrypt_mode": config.get("encrypt_mode", ""),
            "gpo_ps_update": config.get("gpo_ps_update", ""),
        }

# Parse main builds file (non-standard CSV - first row is header inside None key)
builds = []
with open(f"{BASE}/lockbit-builds.csv") as f:
    reader = csv.reader(f)
    header_row = next(reader)  # skip malformed header
    # Real header from the data
    fields = ['id','parent_id','status','description_id','userid','stealerid','comment',
              'master_pubkey','master_privkey','date','company_website','revenue','type',
              'max_file_size','delete_decryptor','created_at','key_id','crypted_website']
    for row in reader:
        if len(row) < 12:
            continue
        b = dict(zip(fields, row))
        b["build_id"] = b.get("id", "")
        b["affiliate_id"] = b.get("userid", "")
        b["build_type"] = b.get("type", "")
        cfg = configs.get(b["build_id"], {})
        b.update(cfg)
        builds.append(b)

with open("output/lockbit_builds_clean.csv", "w", newline="") as f:
    if builds:
        all_keys = list(dict.fromkeys(k for b in builds for k in b.keys()))
        w = csv.DictWriter(f, fieldnames=all_keys, extrasaction='ignore')
        w.writeheader()
        w.writerows(builds)

print(f"  {len(builds)} builds -> output/lockbit_builds_clean.csv")

# Type distribution
type_counts = {}
for b in builds:
    t = b.get("build_type", "?")
    type_counts[t] = type_counts.get(t, 0) + 1
print("  Build types:", type_counts)
print("  (25=basic, 30=Windows full, 40=Windows light, 46=stealer, 47=stealer, 50=ESXi)")

# ============================================================
# 2. AFFILIATES
# ============================================================
print("\nParsing affiliates...")
affiliates = []
with open(f"{BASE}/lockbit-users.csv") as f:
    for r in csv.DictReader(f):
        affiliates.append({
            "id": r.get("id"),
            "login": r.get("login"),
            "is_admin": r.get("is_admin"),
            "paused": r.get("paused"),
            "tag": r.get("tag", ""),
            "created_at": r.get("created_at", ""),
            "last_online": r.get("last_online", ""),
            "paranoid_mode": r.get("paranoid_mode", ""),
            "linesxi_on": r.get("linesxi_on", ""),  # ESXi capability
            "negotiations": r.get("negotiations", ""),
        })

with open("output/lockbit_affiliates.csv", "w", newline="") as f:
    if affiliates:
        w = csv.DictWriter(f, fieldnames=affiliates[0].keys())
        w.writeheader()
        w.writerows(affiliates)

print(f"  {len(affiliates)} affiliates -> output/lockbit_affiliates.csv")
print(f"  Active: {sum(1 for a in affiliates if a['paused']=='0')}")
print(f"  Paused: {sum(1 for a in affiliates if a['paused']=='1')}")

# ============================================================
# 3. RANSOM DEMANDS (invites table)
# ============================================================
print("\nParsing ransom demands...")
invites = []
with open(f"{BASE}/lockbit-invites.csv") as f:
    for r in csv.DictReader(f):
        invites.append({
            "id": r.get("id"),
            "btc_wallet": r.get("btc_wallet", ""),
            "monero_wallet": r.get("monero_wallet", ""),
            "amount_btc": r.get("amount", ""),
            "status": r.get("status", ""),
            "created_at": r.get("created_at", ""),
        })

with open("output/lockbit_ransom_demands.csv", "w", newline="") as f:
    if invites:
        w = csv.DictWriter(f, fieldnames=invites[0].keys())
        w.writeheader()
        w.writerows(invites)

# Analyze amounts
amounts = []
for inv in invites:
    a = inv["amount_btc"]
    if a and a != "NULL":
        amounts.append(float(a))

if amounts:
    print(f"  {len(invites)} invites -> output/lockbit_ransom_demands.csv")
    print(f"  BTC amounts: min={min(amounts):.4f} max={max(amounts):.4f} median={sorted(amounts)[len(amounts)//2]:.4f}")

# ============================================================
# 4. CHAT NEGOTIATIONS (hex-encoded messages)
# ============================================================
print("\nParsing chat negotiations...")
chats = []
with open(f"{BASE}/lockbit-socket-messages.csv") as f:
    for r in csv.DictReader(f):
        hex_data = r.get("request_data", "")
        msg = ""
        if hex_data and hex_data.startswith("0x"):
            raw = bytes.fromhex(hex_data[2:])
            msg = raw.decode("utf-8", errors="replace")

        chats.append({
            "id": r.get("id"),
            "adv_id": r.get("adv_id"),
            "client_id": r.get("client_id"),
            "created_at": r.get("created_at"),
            "message_decoded": msg[:1000],
        })

with open("output/lockbit_negotiations.csv", "w", newline="") as f:
    if chats:
        w = csv.DictWriter(f, fieldnames=chats[0].keys())
        w.writeheader()
        w.writerows(chats)

print(f"  {len(chats)} messages -> output/lockbit_negotiations.csv")

# Show sample decoded messages
print("  Sample decoded messages:")
for c in chats:
    if len(c["message_decoded"]) > 20 and "allread" not in c["message_decoded"]:
        print(f"    [{c['created_at']}] client={c['client_id']}: {c['message_decoded'][:150]}")
        if sum(1 for _ in range(1)) > 10:
            break

# ============================================================
# 5. VICTIM PROFILES (clients table)
# ============================================================
print("\nParsing victim profiles...")
clients = []
with open(f"{BASE}/lockbit-clients.csv") as f:
    for r in csv.DictReader(f):
        clients.append({
            "client_id": r.get("id"),
            "build_id": r.get("build_id"),
            "paid_commission": r.get("paid_commission"),
            "decrypt_done": r.get("decrypt_done"),
            "views": r.get("views"),
            "first_contact": r.get("date_first"),
            "last_contact": r.get("date_last"),
            "created_at": r.get("created_at"),
        })

# Join with builds to get company info
build_map = {b["build_id"]: b for b in builds}
enriched = []
for c in clients:
    b = build_map.get(c["build_id"], {})
    c["company_website"] = b.get("company_website", "")
    c["revenue"] = b.get("revenue", "")
    c["build_type"] = b.get("build_type", "")
    c["affiliate_id"] = b.get("affiliate_id", "")
    enriched.append(c)

with open("output/lockbit_victims_enriched.csv", "w", newline="") as f:
    if enriched:
        w = csv.DictWriter(f, fieldnames=enriched[0].keys())
        w.writeheader()
        w.writerows(enriched)

paid = sum(1 for c in enriched if c["paid_commission"] == "1")
print(f"  {len(enriched)} victims -> output/lockbit_victims_enriched.csv")
print(f"  Paid commission: {paid} ({paid/len(enriched)*100:.1f}%)")

print("\nDone!")
