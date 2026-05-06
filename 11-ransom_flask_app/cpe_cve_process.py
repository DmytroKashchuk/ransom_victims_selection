#!/usr/bin/env python3
"""
=============================================================================
SWDB → CPE → CVE Pipeline (single vendor/product, fully documented)
=============================================================================

Run the entire matching pipeline on a single (vendor, product) pair and
print every intermediate step so you can see exactly what's happening.

Stages:
  STAGE 1 — Normalize input names (strip suffixes, lowercase, etc.)
  STAGE 2 — Download the NVD CPE dictionary
  STAGE 3 — Find the best CPE vendor (6 strategies)
  STAGE 4 — Find the best CPE product under that vendor
  STAGE 5 — Build the CPE match string
  STAGE 6 — Tier 1: query NVD with virtualMatchString
  STAGE 7 — Tier 2: keyword search "vendor product"
  STAGE 8 — Tier 3: keyword search "product"
  STAGE 9 — Validate keyword matches against CVE's own CPE
  STAGE 10 — Annotate KEV (CISA Known Exploited Vulnerabilities)
  STAGE 11 — Print summary

Usage:
    python pipeline_single.py "Check Point" "Quantum Security Gateway"
    python pipeline_single.py "Adobe Systems Inc." "Adobe Photoshop" --api-key KEY
    python pipeline_single.py "Cisco Systems Inc" "Cisco Jabber" --max-cves 50
"""

import argparse, csv, json, os, re, sys, time
from collections import defaultdict, Counter

try:
    import requests
except ImportError:
    sys.exit("Install requests: pip install requests")

# ── Constants ────────────────────────────────────────────────────────
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CPE_DICT_URL = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpedict.csv"

CPE_DICT_PATH = "/Users/dmk6603/Documents/ransom_victims/11-ransom_flask_app/data/tech_cve_normalized/all_cpes.csv"
KEV_CACHE = "kev_catalog.json"

# Score thresholds: below these we say no_match instead of inventing a match
VENDOR_MIN_SCORE = 0.5
PRODUCT_MIN_SCORE = 0.4


# ─────────────────────────────────────────────────────────────────────
# STAGE 1 — Normalize input names
# ─────────────────────────────────────────────────────────────────────

LEGAL_RE = re.compile(
    r',?\s*\b(Inc\.?|LLC\.?|Ltd\.?|GmbH|Corp\.?|PLC|AG|S\.?A\.?|B\.?V\.?|'
    r'Corporation|Incorporated|Limited|Company|Pty|Pvt|Co\.|Foundation)\s*$',
    re.IGNORECASE
)
THE_RE = re.compile(r'^\s*The\s+', re.IGNORECASE)
PAREN_RE = re.compile(r'\s*\([^)]*\)\s*$')
TRAILING_RE = re.compile(r'[\.\,]+$')


def normalize(name):
    """
    Normalize a name for matching.

    Steps:
      - strip legal suffixes (Inc, LLC, Ltd, GmbH, Corp, PLC, AG, etc.)
      - strip the prefix "The"
      - strip trailing parentheticals like "(US)"
      - strip ADR
      - strip trailing punctuation
      - lowercase
      - replace spaces/dashes/dots with underscores

    Run twice to catch stacked suffixes like "Inc ADR".
    """
    n = name.strip()
    for _ in range(2):
        n = re.sub(r'\s+ADR$', '', n)
        n = LEGAL_RE.sub('', n).strip()
        n = THE_RE.sub('', n).strip()
        n = PAREN_RE.sub('', n).strip()
        n = TRAILING_RE.sub('', n).strip()
    return re.sub(r'[\s\-\.]+', '_', n).lower().strip('_')


def tokenize(name):
    """Split a name into lowercase tokens (separators: space, dash, underscore, dot)."""
    return set(re.sub(r'[\s\-\_\.]+', ' ', name.lower()).split())


def jaccard(a, b):
    """Jaccard similarity: |A ∩ B| / |A ∪ B|."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def levenshtein(a, b):
    """Edit distance between two strings."""
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def lev_similarity(a, b):
    """1 - normalized edit distance. Returns 1.0 for identical strings."""
    m = max(len(a), len(b))
    return 1.0 if m == 0 else 1.0 - levenshtein(a, b) / m


# ─────────────────────────────────────────────────────────────────────
# STAGE 2 — Download CPE dictionary
# ─────────────────────────────────────────────────────────────────────

def load_cpe_dict():
    """
    Load (vendor, product, part) tuples from local CPE dictionary CSV.

    Schema: cpe23Uri, part, vendor, product, version, update, edition, ...
    We keep only application (a), OS (o), and hardware (h) entries
    and ignore deprecated ones.
    """
    if not os.path.exists(CPE_DICT_PATH):
        sys.exit(f"CPE file not found: {CPE_DICT_PATH}")

    pairs = set()  # (vendor, product) for matching
    parts_map = defaultdict(set)  # (vendor, product) → {a, o, h}
    deprecated_count = 0

    with open(CPE_DICT_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("deprecated", "").lower() == "true":
                deprecated_count += 1
                continue
            v, p, part = row.get("vendor", "").strip(), row.get("product", "").strip(), row.get("part", "").strip()
            if v and p:
                pairs.add((v, p))
                parts_map[(v, p)].add(part)

    print(f"  Loaded {len(pairs)} unique (vendor, product) pairs ({deprecated_count} deprecated skipped)")
    return pairs, parts_map


def build_index(cpe_pairs):
    """Build lookup structures for fast vendor/product matching."""
    vendors = set()
    v2p = defaultdict(set)
    norm_v = defaultdict(set)
    tok_v = defaultdict(set)

    for v, p in cpe_pairs:
        vendors.add(v)
        v2p[v].add(p)
        norm_v[v].add(v)
        norm_v[v.replace('_', '')].add(v)
        for token in v.split('_'):
            if len(token) > 2:
                tok_v[token].add(v)

    return {"vendors": vendors, "v2p": v2p, "norm_v": norm_v, "tok_v": tok_v}


# ─────────────────────────────────────────────────────────────────────
# STAGE 3 — Find best CPE vendor (6 strategies)
# ─────────────────────────────────────────────────────────────────────

def find_best_vendor(raw_vendor, index, verbose=True):
    """
    Match the SWDB vendor to a CPE vendor using 6 strategies in order:
      1. exact            — identical after normalization
      2. exact_flat       — identical after also stripping underscores
      3. jaccard          — token overlap ratio
      4. substring        — one contained in the other
      5. levenshtein      — edit distance
      6. token_index      — any shared token (last resort)

    Returns (cpe_vendor, score, method).
    """
    norm = normalize(raw_vendor)
    tokens = tokenize(raw_vendor)
    flat = norm.replace('_', '')
    if verbose:
        print(f"  Normalized vendor : '{raw_vendor}' → '{norm}'")
        print(f"  Tokens            : {sorted(tokens)}")
        print(f"  Flat (no _)       : '{flat}'")
        print(f"  CPE vendor space  : {len(index['vendors']):,} unique vendors")
        print(f"")
        print(f"  Strategy ladder (first hit above threshold {VENDOR_MIN_SCORE} wins):")

    # 1. Exact
    if norm in index["vendors"]:
        if verbose:
            print(f"    [1/6] exact         → HIT  '{norm}' (score 1.00)")
            print(f"  → DECISION: vendor='{norm}', method=exact, score=1.00")
        return norm, 1.0, "exact"
    if verbose:
        print(f"    [1/6] exact         → miss")

    # 2. Exact flat
    if flat in index["norm_v"]:
        real = next(iter(index["norm_v"][flat]))
        if verbose:
            print(f"    [2/6] exact_flat    → HIT  '{real}' (score 0.95)")
            print(f"  → DECISION: vendor='{real}', method=exact_flat, score=0.95")
        return real, 0.95, "exact_flat"
    if verbose:
        print(f"    [2/6] exact_flat    → miss")

    candidates = []

    # 3. Jaccard
    for v in index["vendors"]:
        j = jaccard(tokens, set(v.split('_')))
        if j > 0.3:
            candidates.append((v, j, "jaccard"))
    if verbose:
        n = sum(1 for c in candidates if c[2] == "jaccard")
        print(f"    [3/6] jaccard       → {n} candidates (token overlap > 0.30)")

    # 4. Substring (SWDB ⊂ CPE only — avoids tiny CPE vendors matching long SWDB names)
    for v in index["vendors"]:
        if norm in v:
            candidates.append((v, 0.7, "substring"))
    if verbose:
        n = sum(1 for c in candidates if c[2] == "substring")
        print(f"    [4/6] substring     → {n} candidates (norm ⊂ v)")

    # 5. Levenshtein
    if not candidates:
        for v in index["vendors"]:
            sim = lev_similarity(norm, v)
            if sim > 0.7:
                candidates.append((v, sim * 0.8, "levenshtein"))
        if verbose:
            n = sum(1 for c in candidates if c[2] == "levenshtein")
            print(f"    [5/6] levenshtein   → {n} candidates (edit-sim > 0.70)")
    elif verbose:
        print(f"    [5/6] levenshtein   → skipped (already have candidates)")

    # 6. Token index
    if not candidates:
        for token in tokens:
            if len(token) > 3 and token in index["tok_v"]:
                for v in index["tok_v"][token]:
                    candidates.append((v, 0.4, "token_index"))
        if verbose:
            print(f"    [6/6] token_index   → {len(candidates)} candidates (any shared token > 3 chars)")
    elif verbose:
        print(f"    [6/6] token_index   → skipped (already have candidates)")

    if candidates:
        candidates.sort(key=lambda x: -x[1])
        if verbose:
            print(f"")
            print(f"  Top 5 candidates (sorted by score):")
            print(f"  | rank | cpe_vendor                      | method        | score |")
            print(f"  |------|---------------------------------|---------------|-------|")
            for i, (v, s, m) in enumerate(candidates[:5], 1):
                print(f"  | {i:>4} | {v:<31} | {m:<13} | {s:.2f}  |")
        best = candidates[0]
        if best[1] < VENDOR_MIN_SCORE:
            if verbose: print(f"  → DECISION: no_match (best score {best[1]:.2f} < threshold {VENDOR_MIN_SCORE})")
            return "", 0.0, "no_match"
        if verbose: print(f"  → DECISION: vendor='{best[0]}', method={best[2]}, score={best[1]:.2f}")
        return best

    if verbose: print(f"  → DECISION: no_match (no candidates from any strategy)")
    return "", 0.0, "no_match"


# ─────────────────────────────────────────────────────────────────────
# STAGE 4 — Find best CPE product (within vendor's product set)
# ─────────────────────────────────────────────────────────────────────

def find_best_product(raw_product, cpe_vendor, raw_vendor, index, verbose=True):
    """
    Match the SWDB product to a CPE product, restricted to products of cpe_vendor.

    Same strategies as vendor matching. Additionally:
      - strips the vendor name from the product if present
        (e.g. "Cisco Jabber" → "jabber" under cpe_vendor "cisco")
      - strips trailing version numbers (e.g. "Exchange 2013" → "exchange")
    """
    if not cpe_vendor:
        if verbose: print(f"  No vendor → skip product matching")
        return "", 0.0, "no_vendor"

    products = index["v2p"].get(cpe_vendor, set())
    if not products:
        if verbose: print(f"  Vendor {cpe_vendor} has 0 products in NVD → no_vendor_products")
        return "", 0.0, "no_vendor_products"

    norm = normalize(raw_product)
    vendor_norm = normalize(raw_vendor)

    # Strip vendor prefix from product
    if norm.startswith(vendor_norm + '_') and len(norm) > len(vendor_norm) + 1:
        norm_stripped = norm[len(vendor_norm) + 1:]
    else:
        norm_stripped = norm
    # Strip trailing version numbers
    norm_stripped = re.sub(r'_\d[\d\.]*$', '', norm_stripped)

    if verbose:
        print(f"  Normalized product : '{raw_product}' → '{norm}'")
        print(f"  Stripped vendor+ver: '{norm_stripped}'")
        print(f"  Vendor              : '{cpe_vendor}' has {len(products):,} products in NVD")
        print(f"")
        print(f"  Strategy ladder (first hit above threshold {PRODUCT_MIN_SCORE} wins):")

    # 1. Exact
    for try_name in [norm, norm_stripped]:
        if try_name in products:
            if verbose:
                print(f"    [1/5] exact         → HIT  '{try_name}' (score 1.00)")
                print(f"  → DECISION: product='{try_name}', method=exact, score=1.00")
            return try_name, 1.0, "exact"
    if verbose:
        print(f"    [1/5] exact         → miss (tried '{norm}' and '{norm_stripped}')")

    # 2. Exact flat
    for p in products:
        if p.replace('_', '') == norm_stripped.replace('_', ''):
            if verbose:
                print(f"    [2/5] exact_flat    → HIT  '{p}' (score 0.95)")
                print(f"  → DECISION: product='{p}', method=exact_flat, score=0.95")
            return p, 0.95, "exact_flat"
    if verbose:
        print(f"    [2/5] exact_flat    → miss")

    candidates = []

    # 3. Jaccard (remove vendor tokens from product tokens)
    tokens = tokenize(raw_product) - tokenize(raw_vendor)
    if not tokens:
        tokens = tokenize(raw_product)
    for p in products:
        j = jaccard(tokens, set(p.split('_')))
        if j > 0.25:
            candidates.append((p, j, "jaccard"))
    if verbose:
        n = sum(1 for c in candidates if c[2] == "jaccard")
        print(f"    [3/5] jaccard       → {n} candidates (token overlap > 0.25, tokens={sorted(tokens)})")

    # 4. Substring (SWDB ⊂ CPE only — avoids tiny CPE products matching long SWDB names)
    for p in products:
        if norm_stripped in p:
            candidates.append((p, 0.65, "substring"))
    if verbose:
        n = sum(1 for c in candidates if c[2] == "substring")
        print(f"    [4/5] substring     → {n} candidates (norm_stripped ⊂ p)")

    # 5. Levenshtein
    if not candidates:
        for p in products:
            sim = lev_similarity(norm_stripped, p)
            if sim > 0.6:
                candidates.append((p, sim * 0.75, "levenshtein"))
        if verbose:
            n = sum(1 for c in candidates if c[2] == "levenshtein")
            print(f"    [5/5] levenshtein   → {n} candidates (edit-sim > 0.60)")
    elif verbose:
        print(f"    [5/5] levenshtein   → skipped (already have candidates)")

    if candidates:
        candidates.sort(key=lambda x: -x[1])
        if verbose:
            print(f"")
            print(f"  Top 5 candidates (sorted by score):")
            print(f"  | rank | cpe_product                     | method        | score |")
            print(f"  |------|---------------------------------|---------------|-------|")
            for i, (p, s, m) in enumerate(candidates[:5], 1):
                print(f"  | {i:>4} | {p:<31} | {m:<13} | {s:.2f}  |")
        best = candidates[0]
        if best[1] < PRODUCT_MIN_SCORE:
            if verbose: print(f"  → DECISION: no_match (best score {best[1]:.2f} < threshold {PRODUCT_MIN_SCORE})")
            return "", 0.0, "no_match"
        if verbose: print(f"  → DECISION: product='{best[0]}', method={best[2]}, score={best[1]:.2f}")
        return best

    if verbose: print(f"  → DECISION: no_match (no candidates from any strategy)")
    return "", 0.0, "no_match"


# ─────────────────────────────────────────────────────────────────────
# STAGE 6-8 — NVD API queries
# ─────────────────────────────────────────────────────────────────────

def nvd_request(params, api_key=""):
    """Simple NVD API call with retry on 403/503."""
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(3):
        r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
        if r.status_code == 200:
            return r.json()
        if r.status_code in (403, 503):
            wait = 30 * (attempt + 1)
            print(f"    HTTP {r.status_code} — waiting {wait}s")
            time.sleep(wait)
        else:
            print(f"    HTTP {r.status_code}")
            return None
    return None


def fetch_cves(params, api_key="", max_cves=0, delay=6.5):
    """Paginate through NVD results."""
    all_vulns = []
    start = 0
    while True:
        data = nvd_request({**params, "startIndex": start, "resultsPerPage": 2000}, api_key)
        if not data:
            break
        total = data.get("totalResults", 0)
        all_vulns.extend(data.get("vulnerabilities", []))
        if max_cves > 0 and len(all_vulns) >= max_cves:
            all_vulns = all_vulns[:max_cves]
            break
        if len(all_vulns) >= total:
            break
        start = len(all_vulns)
        time.sleep(delay)
    return all_vulns, total if all_vulns else 0


def parse_cve(v):
    """Extract relevant fields from a CVE record."""
    cve = v.get("cve", {})
    cve_id = cve.get("id", "")
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    severity, score = "", ""
    for ver in ["cvssMetricV31", "cvssMetricV30"]:
        if ver in metrics and metrics[ver]:
            cvss = metrics[ver][0].get("cvssData", {})
            score = cvss.get("baseScore", "")
            severity = cvss.get("baseSeverity", "")
            break
    if not severity and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0]
        cvss2 = m.get("cvssData", {})
        score = cvss2.get("baseScore", "")
        severity = m.get("baseSeverity", "")

    vendors, products = set(), set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    vendors.add(parts[3])
                    products.add(parts[4])

    return {
        "cve_id": cve_id,
        "description": desc,
        "base_score": score,
        "severity": severity,
        "published": cve.get("published", "")[:10],
        "cve_vendors": vendors,
        "cve_products": products,
    }


# ─────────────────────────────────────────────────────────────────────
# STAGE 9 — Validate keyword matches
# ─────────────────────────────────────────────────────────────────────

def validate(cve, our_vendor, our_product, vendor_clean, product_clean):
    """
    Decide whether a keyword-matched CVE is really about our product.

    Returns (is_valid, reason).
    """
    cve_vendors = cve.get("cve_vendors", set())
    desc = cve.get("description", "").lower()
    our_v_tokens = set(our_vendor.split("_"))

    if cve_vendors:
        # CVE has CPE configs — require vendor token overlap
        for cv in cve_vendors:
            cv_tokens = set(cv.split("_"))
            overlap = our_v_tokens & cv_tokens
            if len(overlap) >= max(1, len(our_v_tokens) * 0.5):
                return True, "cpe_vendor_match"
        return False, "cpe_vendor_mismatch"

    # No CPE — fall back to description text
    v_pat = re.compile(r'\b' + re.escape(vendor_clean.lower()) + r'\b')
    p_pat = re.compile(r'\b' + re.escape(product_clean.lower()) + r'\b')
    if v_pat.search(desc) and p_pat.search(desc):
        return True, "desc_vendor_and_product"
    if v_pat.search(desc):
        return True, "desc_vendor_only"
    if p_pat.search(desc):
        return True, "desc_product_only"
    return False, "no_evidence"


# ─────────────────────────────────────────────────────────────────────
# STAGE 10 — KEV catalog
# ─────────────────────────────────────────────────────────────────────

def load_kev():
    """Download or load CISA KEV catalog."""
    if os.path.exists(KEV_CACHE):
        age = time.time() - os.path.getmtime(KEV_CACHE)
        if age < 86400:
            with open(KEV_CACHE) as f:
                data = json.load(f)
            return _build_kev(data)

    print("  Downloading CISA KEV...")
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    with open(KEV_CACHE, 'w') as f:
        json.dump(data, f)
    return _build_kev(data)


def _build_kev(data):
    return {v["cveID"]: {
        "date_added": v.get("dateAdded", ""),
        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
    } for v in data.get("vulnerabilities", [])}


# ─────────────────────────────────────────────────────────────────────
# Helper: clean name for keyword search
# ─────────────────────────────────────────────────────────────────────

def clean_for_keyword(name):
    """Strip legal suffixes from a name for keyword search (keeps spaces)."""
    n = name.strip()
    for _ in range(2):
        n = re.sub(r'\s+ADR$', '', n)
        n = LEGAL_RE.sub('', n).strip()
        n = THE_RE.sub('', n).strip()
        n = PAREN_RE.sub('', n).strip()
        n = TRAILING_RE.sub('', n).strip()
    return n


# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

def section(title):
    print(f"\n{'═'*70}\n  {title}\n{'═'*70}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("vendor", help="SWDB vendor name (e.g. 'Adobe Systems Inc.')")
    p.add_argument("product", help="SWDB product name (e.g. 'Adobe Photoshop')")
    p.add_argument("--api-key", default="")
    p.add_argument("--max-cves", type=int, default=20)
    p.add_argument("--no-tier23", action="store_true", help="Skip Tier 2/3 keyword search")
    args = p.parse_args()

    delay = 0.7 if args.api_key else 6.5

    print(f"\n  INPUT")
    print(f"    Vendor:  {args.vendor}")
    print(f"    Product: {args.product}\n")

    # ── STAGE 1+2 ──
    section("STAGE 1 — Normalize input")
    norm_v = normalize(args.vendor)
    norm_p = normalize(args.product)
    print(f"  '{args.vendor}' → '{norm_v}'")
    print(f"  '{args.product}' → '{norm_p}'")

    section("STAGE 2 — Load CPE dictionary")
    cpe_pairs, parts_map = load_cpe_dict()
    index = build_index(cpe_pairs)
    print(f"  {len(index['vendors'])} unique vendors")

    # ── STAGE 3+4 ──
    section("STAGE 3 — Match CPE vendor")
    cpe_v, v_score, v_method = find_best_vendor(args.vendor, index)

    section("STAGE 4 — Match CPE product")
    cpe_p, p_score, p_method = find_best_product(args.product, cpe_v, args.vendor, index)

    final_score = (v_score + p_score) / 2 if cpe_v and cpe_p else 0.0

    # ── STAGE 5 ──
    section("STAGE 5 — Build CPE match string")
    if cpe_v and cpe_p:
        parts = parts_map.get((cpe_v, cpe_p), {"*"})
        print(f"  Available parts in NVD: {sorted(parts)} (a=application, o=OS, h=hardware)")
        # Use wildcard so we cover all parts in one query
        cpe_string = f"cpe:2.3:*:{cpe_v}:{cpe_p}:*:*:*:*:*:*:*"
    else:
        cpe_string = ""
    print(f"  CPE: {cpe_string or '(none — no usable mapping)'}")
    print(f"  Final score: {final_score:.2f}")

    # ── STAGE 10 (load KEV first) ──
    section("STAGE 10 — Load CISA KEV catalog")
    kev = load_kev()
    print(f"  {len(kev)} known exploited CVEs in catalog")

    # ── STAGE 6: Tier 1 ──
    all_cves = {}  # cve_id → record
    section("STAGE 6 — Tier 1: virtualMatchString")
    if cpe_string:
        print(f"  Query: virtualMatchString={cpe_string}")
        vulns, total = fetch_cves({"virtualMatchString": cpe_string}, args.api_key, args.max_cves, delay)
        print(f"  NVD returned {total} CVEs (capped at {args.max_cves})")
        for v in vulns:
            d = parse_cve(v)
            d["match_method"] = "virtualMatchString"
            d["match_tier"] = 1
            d["validated"] = "N/A"
            d["validation_reason"] = "cpe_direct"
            all_cves[d["cve_id"]] = d
        time.sleep(delay)
    else:
        print(f"  Skipped (no CPE)")

    # ── STAGE 7: Tier 2 ──
    if not args.no_tier23:
        section("STAGE 7 — Tier 2: keyword 'vendor product'")
        v_clean = clean_for_keyword(args.vendor)
        p_clean = clean_for_keyword(args.product)
        kw2 = f"{v_clean} {p_clean}" if v_clean.lower() not in p_clean.lower() else p_clean
        print(f"  Query: keywordSearch=\"{kw2}\"")
        vulns, total = fetch_cves({"keywordSearch": kw2}, args.api_key, args.max_cves, delay)
        print(f"  NVD returned {total} CVEs (capped at {args.max_cves})")
        accepted, rejected = 0, 0
        print(f"")
        print(f"  Per-CVE validation against the CVE's own CPE configurations:")
        for v in vulns:
            d = parse_cve(v)
            if d["cve_id"] in all_cves:
                print(f"    ⊘ {d['cve_id']:<18} skip (already matched in Tier 1)")
                continue
            is_valid, reason = validate(d, cpe_v or norm_v, cpe_p or norm_p, v_clean, p_clean)
            if is_valid:
                d["match_method"] = "keyword_vendor_product"
                d["match_tier"] = 2
                d["validated"] = "TRUE"
                d["validation_reason"] = reason
                all_cves[d["cve_id"]] = d
                accepted += 1
                print(f"    ✓ {d['cve_id']:<18} accept ({reason})")
            else:
                rejected += 1
                cve_v_preview = ','.join(sorted(d.get('cve_vendors', []))[:3]) or '(none)'
                print(f"    ✗ {d['cve_id']:<18} reject ({reason}; cve_vendors={cve_v_preview})")
        print(f"")
        print(f"  → DECISION: accepted={accepted}, rejected={rejected}")
        time.sleep(delay)

        # ── STAGE 8: Tier 3 ──
        section("STAGE 8 — Tier 3: keyword 'product' only")
        if v_clean.lower() not in p_clean.lower():
            print(f"  Query: keywordSearch=\"{p_clean}\"")
            vulns, total = fetch_cves({"keywordSearch": p_clean}, args.api_key, args.max_cves, delay)
            print(f"  NVD returned {total} CVEs (capped at {args.max_cves})")
            accepted, rejected = 0, 0
            print(f"")
            print(f"  Per-CVE validation against the CVE's own CPE configurations:")
            for v in vulns:
                d = parse_cve(v)
                if d["cve_id"] in all_cves:
                    print(f"    ⊘ {d['cve_id']:<18} skip (already matched earlier tier)")
                    continue
                is_valid, reason = validate(d, cpe_v or norm_v, cpe_p or norm_p, v_clean, p_clean)
                if is_valid:
                    d["match_method"] = "keyword_product_only"
                    d["match_tier"] = 3
                    d["validated"] = "TRUE"
                    d["validation_reason"] = reason
                    all_cves[d["cve_id"]] = d
                    accepted += 1
                    print(f"    ✓ {d['cve_id']:<18} accept ({reason})")
                else:
                    rejected += 1
                    cve_v_preview = ','.join(sorted(d.get('cve_vendors', []))[:3]) or '(none)'
                    print(f"    ✗ {d['cve_id']:<18} reject ({reason}; cve_vendors={cve_v_preview})")
            print(f"")
            print(f"  → DECISION: accepted={accepted}, rejected={rejected}")
        else:
            print(f"  Skipped (vendor token already inside product name → same query as Tier 2)")
            print(f"  → DECISION: skipped (no new query needed)")

    # ── STAGE 11: Summary ──
    section("STAGE 11 — Summary")

    by_tier = Counter(c["match_tier"] for c in all_cves.values())
    by_sev = Counter(c["severity"] for c in all_cves.values())
    kev_count = sum(1 for c in all_cves.values() if c["cve_id"] in kev)
    ransomware_count = sum(1 for c in all_cves.values()
                           if c["cve_id"] in kev and kev[c["cve_id"]]["ransomware"] == "Known")

    print(f"\n  CPE Mapping")
    print(f"    cpe_vendor:           {cpe_v or '(none)'}")
    print(f"    cpe_product:          {cpe_p or '(none)'}")
    print(f"    cpe_vendor_method:    {v_method}")
    print(f"    cpe_product_method:   {p_method}")
    print(f"    cpe_match_score:      {final_score:.2f}")
    print(f"    cpe_match_string:     {cpe_string or '(none)'}")

    print(f"\n  CVE Counts")
    print(f"    Total unique CVEs:    {len(all_cves)}")
    print(f"    Tier 1 (CPE):         {by_tier.get(1, 0)}")
    print(f"    Tier 2 (kw v+p):      {by_tier.get(2, 0)}")
    print(f"    Tier 3 (kw p):        {by_tier.get(3, 0)}")
    print(f"    Critical:             {by_sev.get('CRITICAL', 0)}")
    print(f"    High:                 {by_sev.get('HIGH', 0)}")
    print(f"    Medium:               {by_sev.get('MEDIUM', 0)}")
    print(f"    Low:                  {by_sev.get('LOW', 0)}")
    print(f"    KEV:                  {kev_count}")
    print(f"    KEV w/ ransomware:    {ransomware_count}")

    if all_cves:
        print(f"\n  CVE Details (first 10):")
        for cve_id in list(all_cves.keys())[:10]:
            c = all_cves[cve_id]
            kev_flag = " [KEV]" if cve_id in kev else ""
            print(f"    {c['cve_id']:<18} T{c['match_tier']}  {c['severity']:<8} "
                  f"{c['base_score']:<5} {c['published']}  {c['validation_reason']}{kev_flag}")

    print()


if __name__ == "__main__":
    main()