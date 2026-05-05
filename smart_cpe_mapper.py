#!/usr/bin/env python3
"""
Smart CPE Mapper — Match technologies to real NVD CPE entries
==============================================================
Downloads the full CPE vendor:product dictionary from NVD,
then uses multi-strategy fuzzy matching to find the best CPE
for each technology in your dataset.

Strategies (in order of confidence):
  1. Exact match after normalization
  2. Token overlap (Jaccard similarity)
  3. Substring containment
  4. Edit distance (Levenshtein)
  5. NVD API keyword search (fallback, slow)

Usage:
    python smart_cpe_mapper.py --input tech_with_cpe_mapping.csv
    python smart_cpe_mapper.py --input tech_with_cpe_mapping.csv --api-key KEY
    python smart_cpe_mapper.py --input tech_with_cpe_mapping.csv --threshold 0.5
"""

import csv, json, re, argparse, os, time
from collections import defaultdict

try:
    import requests
except ImportError:
    import sys; sys.exit("pip install requests")

CPE_DICT_URL = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpedict.csv"
CPE_DICT_CACHE = "cpedict_cache.csv"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
OUTPUT = "tech_with_cpe_mapping_smart.csv"

# ── Legal suffixes to strip ──
LEGAL_RE = re.compile(
    r',?\s*\b(Inc\.?|LLC\.?|Ltd\.?|GmbH|Corp\.?|PLC|AG|S\.?A\.?|B\.?V\.?|'
    r'Corporation|Incorporated|Limited|Company|Pty|Pvt|Co\.)\s*$',
    re.IGNORECASE
)
THE_RE = re.compile(r'^\s*The\s+', re.IGNORECASE)
PAREN_RE = re.compile(r'\s*\([^)]*\)\s*$')
TRAILING_RE = re.compile(r'[\.\,]+$')


def normalize(name):
    """Normalize a name for matching: strip suffixes, lowercase, underscores."""
    n = name.strip()
    for _ in range(2):
        n = re.sub(r'\s+ADR$', '', n)
        n = LEGAL_RE.sub('', n).strip()
        n = THE_RE.sub('', n).strip()
        n = PAREN_RE.sub('', n).strip()
        n = TRAILING_RE.sub('', n).strip()
    return re.sub(r'[\s\-\.]+', '_', n).lower().strip('_')


def tokenize(name):
    """Split into meaningful tokens."""
    return set(re.sub(r'[\s\-\_\.]+', ' ', name.lower()).split())


def jaccard(s1, s2):
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)


def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[len(b)]


def lev_similarity(a, b):
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - levenshtein(a, b) / max_len


# ── CPE Dictionary ──

def download_cpe_dict():
    """Download CPE vendor:product pairs from tiiuae/cpedict."""
    if os.path.exists(CPE_DICT_CACHE):
        age = time.time() - os.path.getmtime(CPE_DICT_CACHE)
        if age < 86400 * 7:  # cache 1 week
            print(f"Using cached CPE dictionary ({CPE_DICT_CACHE})")
            return load_cpe_dict()

    print("Downloading CPE dictionary from GitHub...")
    r = requests.get(CPE_DICT_URL, timeout=60)
    if r.status_code != 200:
        print(f"  Failed ({r.status_code}), trying NVD API fallback...")
        return download_cpe_dict_nvd()

    with open(CPE_DICT_CACHE, 'wb') as f:
        f.write(r.content)
    return load_cpe_dict()


def load_cpe_dict():
    pairs = set()
    with open(CPE_DICT_CACHE) as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2:
                pairs.add((row[0].strip(), row[1].strip()))
    print(f"  Loaded {len(pairs)} vendor:product pairs")
    return pairs


def download_cpe_dict_nvd(api_key=""):
    """Fallback: page through NVD CPE API to build dictionary."""
    print("  Downloading from NVD API (this takes a while)...")
    pairs = set()
    start = 0
    headers = {"apiKey": api_key} if api_key else {}
    while True:
        r = requests.get(NVD_CPE_API, params={"startIndex": start, "resultsPerPage": 10000}, headers=headers, timeout=120)
        if r.status_code != 200:
            break
        data = r.json()
        total = data.get("totalResults", 0)
        for p in data.get("products", []):
            name = p.get("cpe", {}).get("cpeName", "")
            parts = name.split(":")
            if len(parts) >= 5:
                pairs.add((parts[3], parts[4]))
        start += 10000
        print(f"    {len(pairs)} pairs ({start}/{total})...")
        if start >= total:
            break
        time.sleep(0.7 if api_key else 6.5)

    # Cache it
    with open(CPE_DICT_CACHE, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["vendor", "product"])
        for v, p in sorted(pairs):
            w.writerow([v, p])
    print(f"  Downloaded {len(pairs)} pairs")
    return pairs


def build_index(cpe_pairs):
    """Build lookup structures for fast matching."""
    vendor_set = set()
    vendor_to_products = defaultdict(set)
    norm_vendor_map = defaultdict(set)   # normalized → real vendors
    norm_product_map = defaultdict(set)  # normalized → real (vendor, product)
    token_vendor_map = defaultdict(set)  # token → vendors containing that token

    for v, p in cpe_pairs:
        vendor_set.add(v)
        vendor_to_products[v].add(p)
        norm_vendor_map[v].add(v)  # identity
        # Also index by alternative normalizations
        norm_v = re.sub(r'[_\-]', '', v)
        norm_vendor_map[norm_v].add(v)
        norm_product_map[(v, p)].add((v, p))
        norm_p = re.sub(r'[_\-]', '', p)
        norm_product_map[(v, norm_p)].add((v, p))

        for token in v.split('_'):
            if len(token) > 2:
                token_vendor_map[token].add(v)

    return {
        "vendors": vendor_set,
        "v2p": vendor_to_products,
        "norm_v": norm_vendor_map,
        "norm_p": norm_product_map,
        "tok_v": token_vendor_map,
    }


def find_best_vendor(raw_vendor, index):
    """Find the best matching CPE vendor."""
    norm = normalize(raw_vendor)
    candidates = []

    # 1. Exact normalized match
    if norm in index["vendors"]:
        return norm, 1.0, "exact"
    # Without underscores
    norm_flat = norm.replace('_', '')
    if norm_flat in index["norm_v"]:
        real = next(iter(index["norm_v"][norm_flat]))
        return real, 0.95, "exact_flat"

    # 2. Token overlap
    tokens = tokenize(raw_vendor)
    for v in index["vendors"]:
        v_tokens = set(v.split('_'))
        j = jaccard(tokens, v_tokens)
        if j > 0.3:
            candidates.append((v, j, "jaccard"))

    # 3. Substring
    for v in index["vendors"]:
        if norm in v or v in norm:
            candidates.append((v, 0.7, "substring"))

    # 4. Levenshtein on top candidates
    if not candidates:
        for v in index["vendors"]:
            sim = lev_similarity(norm, v)
            if sim > 0.7:
                candidates.append((v, sim * 0.8, "levenshtein"))

    # 5. Token index lookup
    if not candidates:
        for token in tokenize(raw_vendor):
            if len(token) > 3 and token in index["tok_v"]:
                for v in index["tok_v"][token]:
                    candidates.append((v, 0.4, "token_index"))

    if candidates:
        candidates.sort(key=lambda x: -x[1])
        return candidates[0]

    return norm, 0.0, "no_match"


def find_best_product(raw_product, cpe_vendor, raw_vendor, index):
    """Find the best matching CPE product under a given vendor."""
    products = index["v2p"].get(cpe_vendor, set())
    if not products:
        return normalize(raw_product), 0.0, "no_vendor_products"

    norm = normalize(raw_product)
    # Strip vendor prefix from product
    vendor_norm = normalize(raw_vendor)
    if norm.startswith(vendor_norm + '_') and len(norm) > len(vendor_norm) + 1:
        norm_stripped = norm[len(vendor_norm) + 1:]
    else:
        norm_stripped = norm
    # Also strip version numbers
    norm_stripped = re.sub(r'_\d[\d\.]*$', '', norm_stripped)

    candidates = []

    # 1. Exact match (with or without vendor prefix)
    for try_name in [norm, norm_stripped]:
        if try_name in products:
            return try_name, 1.0, "exact"

    # 2. Flat match (no underscores)
    for p in products:
        if p.replace('_', '') == norm_stripped.replace('_', ''):
            return p, 0.95, "exact_flat"

    # 3. Token overlap
    tokens = tokenize(raw_product) - tokenize(raw_vendor)  # remove vendor tokens
    if not tokens:
        tokens = tokenize(raw_product)
    for p in products:
        p_tokens = set(p.split('_'))
        j = jaccard(tokens, p_tokens)
        if j > 0.25:
            candidates.append((p, j, "jaccard"))

    # 4. Substring
    for p in products:
        if norm_stripped in p or p in norm_stripped:
            candidates.append((p, 0.65, "substring"))

    # 5. Levenshtein
    if not candidates:
        for p in products:
            sim = lev_similarity(norm_stripped, p)
            if sim > 0.6:
                candidates.append((p, sim * 0.75, "levenshtein"))

    if candidates:
        candidates.sort(key=lambda x: -x[1])
        return candidates[0]

    return norm_stripped if norm_stripped else norm, 0.0, "no_match"


def search_nvd_api(vendor, product, api_key="", delay=6.5):
    """Last resort: search NVD CPE API by keyword."""
    headers = {"apiKey": api_key} if api_key else {}
    kw = f"{vendor} {product}".replace('_', ' ')
    r = requests.get(NVD_CPE_API, params={"keywordSearch": kw, "resultsPerPage": 5}, headers=headers, timeout=30)
    if r.status_code == 200:
        data = r.json()
        for p in data.get("products", []):
            name = p.get("cpe", {}).get("cpeName", "")
            parts = name.split(":")
            if len(parts) >= 5:
                return parts[3], parts[4], 0.6, "nvd_api"
    return None, None, 0, "nvd_api_fail"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="tech_with_cpe_mapping.csv")
    p.add_argument("--output", default=OUTPUT)
    p.add_argument("--api-key", default="")
    p.add_argument("--threshold", type=float, default=0.0, help="Min score to accept (0=keep all)")
    p.add_argument("--api-fallback", action="store_true", help="Use NVD API for unmatched")
    p.add_argument("--limit", type=int, default=0)
    args = p.parse_args()

    # Load CPE dictionary
    cpe_pairs = download_cpe_dict()
    index = build_index(cpe_pairs)
    print(f"  Indexed {len(index['vendors'])} vendors\n")

    # Load technologies
    with open(args.input) as f:
        techs = list(csv.DictReader(f))
    if args.limit:
        techs = techs[:args.limit]
    print(f"Processing {len(techs)} technologies...\n")

    stats = {"exact": 0, "fuzzy": 0, "api": 0, "no_match": 0, "improved": 0}

    for i, tech in enumerate(techs):
        raw_vendor = tech["VendorName"]
        raw_product = tech["Product"]
        old_v = tech["cpe_vendor"]
        old_p = tech["cpe_product"]

        # Match vendor
        best_v, v_score, v_method = find_best_vendor(raw_vendor, index)

        # Match product under that vendor
        best_p, p_score, p_method = find_best_product(raw_product, best_v, raw_vendor, index)

        combined_score = (v_score + p_score) / 2

        # API fallback for poor matches
        if combined_score < 0.3 and args.api_fallback:
            api_v, api_p, api_score, api_method = search_nvd_api(
                raw_vendor, raw_product, args.api_key)
            if api_v and api_score > combined_score:
                best_v, best_p = api_v, api_p
                combined_score = api_score
                v_method, p_method = api_method, api_method
                stats["api"] += 1
            delay = 0.7 if args.api_key else 6.5
            time.sleep(delay)

        # Track stats
        if combined_score >= 0.9:
            stats["exact"] += 1
        elif combined_score > 0:
            stats["fuzzy"] += 1
        else:
            stats["no_match"] += 1

        changed = (best_v != old_v or best_p != old_p)
        if changed and combined_score > 0.3:
            stats["improved"] += 1

        # Update
        tech["cpe_vendor"] = best_v
        tech["cpe_product"] = best_p
        tech["cpe_match_string"] = f"cpe:2.3:a:{best_v}:{best_p}:*:*:*:*:*:*:*"
        tech["cpe_match_score"] = f"{combined_score:.2f}"
        tech["cpe_vendor_method"] = v_method
        tech["cpe_product_method"] = p_method

        if (i + 1) % 500 == 0:
            print(f"  [{i+1}/{len(techs)}] exact={stats['exact']} fuzzy={stats['fuzzy']} no_match={stats['no_match']}")

        # Log interesting cases
        if changed and combined_score > 0.3 and (i < 50 or combined_score < 0.7):
            print(f"  {raw_vendor} | {raw_product}")
            print(f"    old: {old_v}:{old_p}")
            print(f"    new: {best_v}:{best_p} (v={v_score:.2f}/{v_method} p={p_score:.2f}/{p_method})")

    # Write output
    fields = list(techs[0].keys())
    for extra in ["cpe_match_score", "cpe_vendor_method", "cpe_product_method"]:
        if extra not in fields:
            fields.append(extra)

    with open(args.output, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(techs)

    print(f"\n{'='*60}")
    print(f"Done! {len(techs)} technologies processed")
    print(f"  Exact matches:  {stats['exact']}")
    print(f"  Fuzzy matches:  {stats['fuzzy']}")
    print(f"  API fallback:   {stats['api']}")
    print(f"  No match:       {stats['no_match']}")
    print(f"  Improved:       {stats['improved']} (changed from old mapping)")
    print(f"\nOutput: {args.output}")
    print(f"Check 'cpe_match_score' column — lower scores need manual review")


if __name__ == "__main__":
    main()