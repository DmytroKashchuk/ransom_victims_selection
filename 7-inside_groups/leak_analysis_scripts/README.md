# Ransomware Leak Analysis Scripts

Scripts per estrarre dati sulla victim selection da Conti, Black Basta e LockBit leaks.

## Setup

```bash
# Clona i dataset nella stessa directory degli scripts
git clone https://github.com/TheParmak/conti-leaks-englished.git
git clone https://github.com/D4RK-R4BB1T/BlackBasta-Chats.git
git clone https://github.com/Hexastrike/LockBit-Database-Leak-2025.git

# Struttura attesa:
# .
# ├── conti-leaks-englished/
# ├── BlackBasta-Chats/
# ├── LockBit-Database-Leak-2025/
# ├── scripts/
# └── output/          <- creato automaticamente
```

## Scripts

### 1. `extract_victims.py`
Estrae profili vittime da tutti e 3 i leak in un CSV unificato.
- **Output**: `output/victims_unified.csv`
- Campi: source, date, sender, domain, revenue, servers, computers, zoominfo_url, sector, country

### 2. `extract_tech_targeting.py`  
Estrae keyword tecnologiche, CVE e tool di recon.
- **Output**: `output/tech_keywords.csv`, `output/cves_mentioned.csv`, `output/recon_tools.csv`, `output/domains_mentioned.csv`
- ~60 keyword tecnologiche tracciate (Citrix, SonicWall, Fortinet, VPN, RDP, ESXi, ecc.)

### 3. `extract_domains_for_httparchive.py`
Lista pulita di domini vittime pronta per il join con HTTP Archive/BigQuery.
- **Output**: `output/victim_domains_for_httparchive.csv`
- Campi: domain, groups, sources, revenue, first_seen, last_seen, mention_count
- Filtri applicati: rimossi test, fake, localhost, onion

### 4. `extract_lockbit_structured.py`
Dati strutturati dal dump SQL di LockBit.
- **Output**: `output/lockbit_builds_clean.csv`, `output/lockbit_affiliates.csv`, `output/lockbit_ransom_demands.csv`, `output/lockbit_negotiations.csv`, `output/lockbit_victims_enriched.csv`
- Include: build configs (kill lists, spread options), affiliati, negoziazioni decodificate, vittime con payment status

## Uso con BigQuery / HTTP Archive

```sql
-- Esempio: join victim domains con HTTP Archive
WITH victims AS (
  SELECT domain FROM `your_project.dataset.victim_domains_for_httparchive`
)
SELECT
  t.url, t.category, t.app,
  v.domain
FROM `httparchive.technologies.2024_01_01_*` t
JOIN victims v ON NET.REG_DOMAIN(t.url) = v.domain
```

## Build Types (LockBit)
- 25 = Basic (solo website + revenue)
- 30 = Windows full locker (kill lists, spread, GPO)
- 40 = Windows light
- 46/47 = Stealer
- 50 = ESXi/Linux locker
