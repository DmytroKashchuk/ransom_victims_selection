#!/usr/bin/env python3
"""
CVE Lookup — Search NVD CVE Database
======================================
Usage:
    python cve_lookup.py --id CVE-2024-24919
    python cve_lookup.py --keyword "check point vpn"
    python cve_lookup.py --cpe "cpe:2.3:a:checkpoint:quantum_security_gateway_firmware:*"
    python cve_lookup.py --keyword "log4j" --severity CRITICAL
    python cve_lookup.py --keyword "apache" --from 2024-01-01 --to 2024-12-31
    python cve_lookup.py --cpe "cpe:2.3:a:microsoft:exchange_server:*" --limit 10 --api-key KEY
"""

import argparse, requests, json

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search(params, api_key=""):
    headers = {"apiKey": api_key} if api_key else {}
    r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
    if r.status_code == 200:
        return r.json()
    print(f"Error: {r.status_code}")
    return None

def parse_cve(v):
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
        cvss2 = metrics["cvssMetricV2"][0].get("cvssData", {})
        score = cvss2.get("baseScore", "")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "")
    published = cve.get("published", "")[:10]
    vendors, products = set(), set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    vendors.add(parts[3])
                    products.add(parts[4])
    return cve_id, score, severity, published, vendors, products, desc

def main():
    p = argparse.ArgumentParser(description="Search NVD CVE Database")
    p.add_argument("--id", "-i", help="Exact CVE ID (e.g. CVE-2024-24919)")
    p.add_argument("--keyword", "-k", help="Keyword search in descriptions")
    p.add_argument("--cpe", help="CPE match string (e.g. cpe:2.3:a:vendor:product:*)")
    p.add_argument("--severity", "-s", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--from", dest="pub_from", help="Published after (YYYY-MM-DD)")
    p.add_argument("--to", dest="pub_to", help="Published before (YYYY-MM-DD)")
    p.add_argument("--kev", action="store_true", help="Only show CISA KEV entries")
    p.add_argument("--limit", "-n", type=int, default=20)
    p.add_argument("--full", "-f", action="store_true", help="Show full descriptions")
    p.add_argument("--json", "-j", action="store_true", help="Raw JSON output")
    p.add_argument("--api-key", default="")
    args = p.parse_args()

    params = {"resultsPerPage": min(args.limit, 2000)}

    if args.id:
        params["cveId"] = args.id
    elif args.cpe:
        params["virtualMatchString"] = args.cpe
    elif args.keyword:
        params["keywordSearch"] = args.keyword
    else:
        p.print_help()
        return

    if args.severity:
        params["cvssV3Severity"] = args.severity
    if args.pub_from:
        params["pubStartDate"] = f"{args.pub_from}T00:00:00.000"
    if args.pub_to:
        params["pubEndDate"] = f"{args.pub_to}T23:59:59.999"
    if args.kev:
        params["hasKev"] = ""

    # Load KEV for flagging
    kev_set = set()
    try:
        import os
        if os.path.exists("kev_catalog.json"):
            with open("kev_catalog.json") as f:
                for v in json.load(f).get("vulnerabilities", []):
                    kev_set.add(v.get("cveID", ""))
    except:
        pass

    data = search(params, args.api_key)
    if not data:
        return

    if args.json:
        print(json.dumps(data, indent=2))
        return

    total = data.get("totalResults", 0)
    vulns = data.get("vulnerabilities", [])

    print(f"\n{total} results (showing {len(vulns)})\n")

    for v in vulns:
        cve_id, score, severity, published, vendors, products, desc = parse_cve(v)
        kev_flag = " [KEV]" if cve_id in kev_set else ""
        sev_str = f"{severity} ({score})" if severity else "N/A"

        print(f"{'─'*80}")
        print(f"  {cve_id}  |  {sev_str}  |  {published}{kev_flag}")
        if vendors:
            print(f"  Vendors:  {', '.join(sorted(vendors))}")
        if products:
            print(f"  Products: {', '.join(sorted(products))}")
        trunc = desc if args.full else desc[:200] + ("..." if len(desc) > 200 else "")
        print(f"  {trunc}")

    print(f"{'─'*80}")
    print(f"\n{total} total | showing {len(vulns)} | use --limit N for more")

if __name__ == "__main__":
    main()