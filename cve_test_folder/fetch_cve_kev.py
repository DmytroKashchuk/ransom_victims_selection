#!/usr/bin/env python3
"""
CVE Fetcher v4 — Full metadata + KEV + 3 tiers
================================================
All 3 lookup tiers with match_method column for easy filtering.
Outputs ALL linking data: CPE vendor/product, match string used, KEV status.

Usage:
    python fetch_cves_v4.py --input tech_with_cpe_mapping_fixed.csv
    python fetch_cves_v4.py --input tech_with_cpe_mapping_fixed.csv --api-key KEY
    python fetch_cves_v4.py --input tech_with_cpe_mapping_fixed.csv --resume
"""

import csv, json, time, argparse, os, sys, re

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = "kev_catalog.json"
PAGE_SIZE = 2000
CHECKPOINT_FILE = "fetch_progress_v4.json"
RESULTS_FILE = "tech_cve_results_v4.csv"
SUMMARY_FILE = "tech_cve_summary_v4.csv"

RESULT_FIELDS = [
    "VendorName", "Product", "ProductCategory", "ProductSeries",
    "cpe_vendor", "cpe_product", "cpe_match_string_used",
    "cve_id", "base_score", "severity", "published_date", "description",
    "match_method", "match_tier", "keyword_validated", "validation_reason",
    "kev", "kev_date_added", "kev_due_date", "kev_ransomware",
    "cve_vendors", "cve_products",
]

SUMMARY_FIELDS = [
    "VendorName", "Product", "ProductCategory", "ProductSeries",
    "cpe_vendor", "cpe_product", "cpe_match_string",
    "total_cves", "total_available_in_nvd",
    "tier1_cves", "tier2_cves", "tier3_cves",
    "critical", "high", "medium", "low",
    "kev_count", "kev_ransomware_count",
    "match_method",
]


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="tech_with_cpe_mapping_fixed.csv")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--category", type=str, default="")
    p.add_argument("--api-key", type=str, default="")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--delay", type=float, default=6.5)
    p.add_argument("--max-cves", type=int, default=0)
    p.add_argument("--no-kev", action="store_true", help="Skip KEV download")
    return p.parse_args()


# ── KEV ──

def load_kev(skip=False):
    if skip:
        return {}
    if os.path.exists(KEV_CACHE):
        age = time.time() - os.path.getmtime(KEV_CACHE)
        if age < 86400:
            with open(KEV_CACHE) as f:
                data = json.load(f)
            print(f"KEV: cached, {len(data.get('vulnerabilities', []))} entries")
            return _build_kev_lookup(data)
    print("KEV: downloading from CISA...")
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    with open(KEV_CACHE, 'w') as f:
        json.dump(data, f)
    print(f"KEV: {len(data.get('vulnerabilities', []))} entries")
    return _build_kev_lookup(data)


def _build_kev_lookup(data):
    lookup = {}
    for v in data.get("vulnerabilities", []):
        lookup[v.get("cveID", "")] = {
            "kev_date_added": v.get("dateAdded", ""),
            "kev_due_date": v.get("dueDate", ""),
            "kev_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
        }
    return lookup


# ── NVD API ──

def _do_request(params, api_key="", max_retries=3):
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 503):
                wait = 30 * attempt
                print(f"    [WARN] {resp.status_code} — sleeping {wait}s (attempt {attempt})")
                time.sleep(wait)
            else:
                print(f"    [WARN] status {resp.status_code}")
                return None
        except requests.exceptions.Timeout:
            time.sleep(10 * attempt)
        except Exception as e:
            print(f"    [ERROR] {e}")
            return None
    return None


def _paginated_fetch(params, api_key="", delay=6.5, max_cves=0):
    all_vulns, start_index, total_results = [], 0, None
    while True:
        data = _do_request({**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}, api_key)
        if not data:
            break
        total_results = data.get("totalResults", 0)
        all_vulns.extend(data.get("vulnerabilities", []))
        if total_results > PAGE_SIZE:
            print(f"    Fetched {len(all_vulns)}/{total_results}...")
        if max_cves > 0 and len(all_vulns) >= max_cves:
            all_vulns = all_vulns[:max_cves]
            break
        if len(all_vulns) >= total_results:
            break
        start_index = len(all_vulns)
        time.sleep(delay)
    return all_vulns, total_results or 0


def extract_cve_details(vuln_data):
    cve = vuln_data.get("cve", {})
    cve_id = cve.get("id", "")
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    severity, base_score = "", ""
    for ver in ["cvssMetricV31", "cvssMetricV30"]:
        if ver in metrics and metrics[ver]:
            cvss = metrics[ver][0].get("cvssData", {})
            base_score = cvss.get("baseScore", "")
            severity = cvss.get("baseSeverity", "")
            break
    if not severity and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss2 = metrics["cvssMetricV2"][0].get("cvssData", {})
        base_score = cvss2.get("baseScore", "")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "")

    # Extract affected vendors/products from CPE configurations
    vendors, products = set(), set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendors.add(parts[3])
                    products.add(parts[4])

    return {
        "cve_id": cve_id,
        "description": desc[:500],
        "base_score": base_score,
        "severity": severity,
        "published_date": cve.get("published", "")[:10],
        "cve_vendors": "; ".join(sorted(vendors)),
        "cve_products": "; ".join(sorted(products)),
        "_raw_vendors": vendors,
        "_raw_products": products,
    }


def validate_keyword_match(cve_details, cpe_vendor, cpe_product, vendor_name, product_name):
    """
    Check if a keyword-matched CVE actually relates to our vendor/product.
    Returns (is_valid, reason).

    Checks:
    1. CPE vendor/product tokens overlap with ours
    2. Description contains vendor AND product as whole words
    3. Reject if CPE configs exist but don't mention our vendor at all
    """
    cve_vendors = cve_details.get("_raw_vendors", set())
    cve_products = cve_details.get("_raw_products", set())
    desc = cve_details.get("description", "").lower()

    our_vendor_tokens = set(cpe_vendor.split("_"))
    our_product_tokens = set(cpe_product.split("_"))

    # If CVE has CPE configs, check for vendor overlap
    if cve_vendors:
        vendor_match = False
        for cv in cve_vendors:
            cv_tokens = set(cv.split("_"))
            overlap = our_vendor_tokens & cv_tokens
            if len(overlap) >= max(1, len(our_vendor_tokens) * 0.5):
                vendor_match = True
                break
        if vendor_match:
            return True, "cpe_vendor_match"

        # CPE configs exist but our vendor not found — likely false positive
        return False, "cpe_vendor_mismatch"

    # No CPE configs (CVE awaiting analysis) — check description
    # Require vendor name as whole word in description
    v_pattern = re.compile(r'\b' + re.escape(vendor_name.lower()) + r'\b')
    p_pattern = re.compile(r'\b' + re.escape(product_name.lower()) + r'\b')

    v_in_desc = bool(v_pattern.search(desc))
    p_in_desc = bool(p_pattern.search(desc))

    if v_in_desc and p_in_desc:
        return True, "desc_vendor_and_product"
    if v_in_desc:
        return True, "desc_vendor_only"

    # Product-only match in description — weak, but flag it
    if p_in_desc:
        return True, "desc_product_only"

    return False, "no_evidence"


# ── Checkpoint ──

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE) as f:
            return json.load(f)
    return {"completed": [], "last_index": 0}


def save_checkpoint(cp):
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(cp, f)


# ── Main ──

def main():
    args = parse_args()
    delay = args.delay if not args.api_key else max(0.7, args.delay / 10)

    kev_lookup = load_kev(skip=args.no_kev)

    with open(args.input) as f:
        techs = list(csv.DictReader(f))
    if args.category:
        techs = [t for t in techs if t["ProductCategory"] == args.category]
    if args.limit > 0:
        techs = techs[:args.limit]

    print(f"\nProcessing {len(techs)} technologies | delay={delay}s | api_key={'yes' if args.api_key else 'no'}\n")

    checkpoint = load_checkpoint() if args.resume else {"completed": [], "last_index": 0}
    completed_set = set(checkpoint["completed"])
    start_idx = checkpoint["last_index"] if args.resume else 0
    results_mode = 'a' if args.resume and os.path.exists(RESULTS_FILE) else 'w'
    summary_rows = []

    with open(RESULTS_FILE, results_mode, newline='') as rf:
        writer = csv.DictWriter(rf, fieldnames=RESULT_FIELDS, extrasaction='ignore')
        if results_mode == 'w':
            writer.writeheader()

        for i, tech in enumerate(techs[start_idx:], start=start_idx):
            key = f"{tech['VendorName']}|{tech['Product']}"
            if key in completed_set:
                continue

            vendor = tech["VendorName"]
            product = tech["Product"]
            cpe_vendor = tech["cpe_vendor"]
            cpe_product = tech["cpe_product"]
            category = tech["ProductCategory"]
            series = tech.get("ProductSeries", "")

            print(f"[{i+1}/{len(techs)}] {vendor} — {product} ({cpe_vendor}:{cpe_product})")

            all_cve_ids = set()
            tier_counts = {"tier1": 0, "tier2": 0, "tier3": 0}
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            kev_count = 0
            kev_ransomware_count = 0
            final_method = "no_match"

            def write_vulns(vulns, method, tier, match_string):
                nonlocal kev_count, kev_ransomware_count, final_method
                new_vulns = 0
                skipped = 0
                for v in vulns:
                    d = extract_cve_details(v)
                    if d["cve_id"] in all_cve_ids:
                        continue

                    # Validate keyword matches against CPE configs
                    kw_validated = ""
                    validation_reason = ""
                    if tier >= 2:
                        is_valid, reason = validate_keyword_match(
                            d, cpe_vendor, cpe_product, vendor, product)
                        kw_validated = "TRUE" if is_valid else "FALSE"
                        validation_reason = reason
                        if not is_valid:
                            skipped += 1
                            continue
                    else:
                        kw_validated = "N/A"
                        validation_reason = "cpe_direct"

                    all_cve_ids.add(d["cve_id"])
                    new_vulns += 1

                    sev = d["severity"].upper()
                    if sev in sev_counts:
                        sev_counts[sev] += 1

                    kev_info = kev_lookup.get(d["cve_id"], {})
                    is_kev = bool(kev_info)
                    if is_kev:
                        kev_count += 1
                        if kev_info.get("kev_ransomware") == "Known":
                            kev_ransomware_count += 1

                    # Remove internal fields before writing
                    d.pop("_raw_vendors", None)
                    d.pop("_raw_products", None)

                    writer.writerow({
                        "VendorName": vendor,
                        "Product": product,
                        "ProductCategory": category,
                        "ProductSeries": series,
                        "cpe_vendor": cpe_vendor,
                        "cpe_product": cpe_product,
                        "cpe_match_string_used": match_string,
                        "match_method": method,
                        "match_tier": tier,
                        "keyword_validated": kw_validated,
                        "validation_reason": validation_reason,
                        "kev": "TRUE" if is_kev else "FALSE",
                        "kev_date_added": kev_info.get("kev_date_added", ""),
                        "kev_due_date": kev_info.get("kev_due_date", ""),
                        "kev_ransomware": kev_info.get("kev_ransomware", ""),
                        **d,
                    })

                tier_counts[f"tier{tier}"] = new_vulns
                if new_vulns > 0 and final_method == "no_match":
                    final_method = method
                if skipped > 0:
                    print(f"    Tier {tier}: filtered out {skipped} false positives")
                return new_vulns

            # ── Tier 1: virtualMatchString ──
            virtual_cpe = f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:*:*:*:*:*:*:*"
            vulns1, total1 = _paginated_fetch({"virtualMatchString": virtual_cpe}, args.api_key, delay, args.max_cves)
            n1 = write_vulns(vulns1, "virtualMatchString", 1, virtual_cpe)
            if total1 > 0:
                print(f"    Tier 1 (CPE): {total1} total, {n1} new")
            time.sleep(delay)

            # ── Tier 2: keyword vendor+product ──
            search2 = f"{vendor} {product}" if vendor.lower() not in product.lower() else product
            vulns2, total2 = _paginated_fetch({"keywordSearch": search2}, args.api_key, delay, args.max_cves)
            n2 = write_vulns(vulns2, "keyword_vendor_product", 2, f"keyword:\"{search2}\"")
            if n2 > 0:
                print(f"    Tier 2 (keyword v+p): {total2} total, {n2} new (after dedup)")
            time.sleep(delay)

            # ── Tier 3: keyword product only ──
            if vendor.lower() not in product.lower():
                vulns3, total3 = _paginated_fetch({"keywordSearch": product}, args.api_key, delay, args.max_cves)
                n3 = write_vulns(vulns3, "keyword_product_only", 3, f"keyword:\"{product}\"")
                if n3 > 0:
                    print(f"    Tier 3 (keyword p): {total3} total, {n3} new (after dedup)")
                time.sleep(delay)

            rf.flush()

            total_cves = len(all_cve_ids)
            sev_str = f" ({sev_counts['CRITICAL']}C/{sev_counts['HIGH']}H/{sev_counts['MEDIUM']}M/{sev_counts['LOW']}L)" if total_cves else ""
            kev_str = f" | {kev_count} KEV" if kev_count else ""
            print(f"    TOTAL: {total_cves} CVEs{sev_str}{kev_str}")

            summary_rows.append({
                "VendorName": vendor,
                "Product": product,
                "ProductCategory": category,
                "ProductSeries": series,
                "cpe_vendor": cpe_vendor,
                "cpe_product": cpe_product,
                "cpe_match_string": virtual_cpe,
                "total_cves": total_cves,
                "total_available_in_nvd": total1,
                "tier1_cves": tier_counts["tier1"],
                "tier2_cves": tier_counts["tier2"],
                "tier3_cves": tier_counts["tier3"],
                "critical": sev_counts["CRITICAL"],
                "high": sev_counts["HIGH"],
                "medium": sev_counts["MEDIUM"],
                "low": sev_counts["LOW"],
                "kev_count": kev_count,
                "kev_ransomware_count": kev_ransomware_count,
                "match_method": final_method,
            })

            completed_set.add(key)
            if (i + 1) % 25 == 0:
                save_checkpoint({"completed": list(completed_set), "last_index": i + 1})
                print(f"    [Checkpoint saved at {i+1}]")

    # ── Write summary ──
    with open(SUMMARY_FILE, 'w', newline='') as sf:
        w = csv.DictWriter(sf, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        w.writerows(summary_rows)

    total_cves = sum(r["total_cves"] for r in summary_rows)
    with_cves = sum(1 for r in summary_rows if r["total_cves"] > 0)
    total_kev = sum(r["kev_count"] for r in summary_rows)
    total_ransomware = sum(r["kev_ransomware_count"] for r in summary_rows)
    t1 = sum(r["tier1_cves"] for r in summary_rows)
    t2 = sum(r["tier2_cves"] for r in summary_rows)
    t3 = sum(r["tier3_cves"] for r in summary_rows)

    print(f"\n{'='*60}")
    print(f"Done! {len(summary_rows)} technologies processed")
    print(f"  {with_cves} with known CVEs | {total_cves} total CVEs")
    print(f"  Tier 1 (CPE):        {t1} CVEs")
    print(f"  Tier 2 (kw v+p):     {t2} CVEs")
    print(f"  Tier 3 (kw p only):  {t3} CVEs")
    print(f"  KEV:                 {total_kev} CVEs in CISA KEV")
    print(f"  Ransomware:          {total_ransomware} CVEs with known ransomware use")
    print(f"\n  {RESULTS_FILE}  — one row per CVE (full metadata)")
    print(f"  {SUMMARY_FILE}  — one row per technology")


if __name__ == "__main__":
    main()