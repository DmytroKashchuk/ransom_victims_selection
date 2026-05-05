#!/usr/bin/env python3
"""
CPE Lookup — Search NVD CPE Dictionary (enriched)
==================================================
Usage:
    python cpe_lookup.py --keyword "check point"
    python cpe_lookup.py --cpe "cpe:2.3:a:bufferlist_project:bufferlist:*:*:*:*:*:*:*:*"
    python cpe_lookup.py --vendor checkpoint --product quantum --details
    python cpe_lookup.py --keyword "bufferlist" --details --cves
"""

import argparse
import re
import sys
import time
import requests

NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "codeberg.org")


def http_get(url, params, api_key="", retries=3):
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(retries):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=30)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429):
                time.sleep(6 * (attempt + 1))
                continue
            print(f"  ! HTTP {r.status_code} on {url}", file=sys.stderr)
            return None
        except requests.RequestException as e:
            print(f"  ! {e}", file=sys.stderr)
            time.sleep(2)
    return None


def classify_ref(url):
    u = url.lower()
    for host in REPO_HOSTS:
        if host in u:
            return "repo"
    if any(k in u for k in ("advisor", "cve", "security", "bulletin")):
        return "advisory"
    if any(k in u for k in ("changelog", "release", "commit", "tag")):
        return "changelog"
    return "other"


def pick_title(titles):
    if not titles:
        return ""
    for t in titles:
        if t.get("lang") == "en":
            return t.get("title", "")
    return titles[0].get("title", "")


def extract_refs(refs):
    out = {"repo": [], "advisory": [], "changelog": [], "vendor": [], "other": []}
    for ref in refs or []:
        url = ref.get("ref", "")
        declared = (ref.get("type") or "").lower()
        kind = classify_ref(url)
        if declared == "vendor" and kind == "other":
            kind = "vendor"
        out.setdefault(kind, []).append(url)
    return out


def count_cves(cpe_name, api_key):
    data = http_get(NVD_CVE_API, {"cpeName": cpe_name, "resultsPerPage": 1}, api_key)
    if not data:
        return None
    return data.get("totalResults", 0)


def print_product(prod, show_details, show_cves, api_key):
    cpe = prod.get("cpe", {})
    name = cpe.get("cpeName", "")
    parts = name.split(":")
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    title = pick_title(cpe.get("titles"))
    deprecated = cpe.get("deprecated", False)

    print(f"\n● {vendor} / {product}")
    print(f"  CPE:        {name}")
    if title:
        print(f"  Title:      {title}")
    print(f"  Created:    {cpe.get('created', '-')[:10]}    "
          f"Modified: {cpe.get('lastModified', '-')[:10]}")
    if deprecated:
        dep_by = [d.get("cpeName", "") for d in cpe.get("deprecatedBy", [])]
        print(f"  ⚠ DEPRECATED → {', '.join(dep_by) or 'n/a'}")

    if show_details:
        refs = extract_refs(cpe.get("refs"))
        if refs["repo"]:
            print(f"  Repo:       {refs['repo'][0]}")
            for extra in refs["repo"][1:]:
                print(f"              {extra}")
        if refs["vendor"]:
            print(f"  Vendor URL: {refs['vendor'][0]}")
        if refs["advisory"]:
            print(f"  Advisories: {len(refs['advisory'])}")
            for a in refs["advisory"][:3]:
                print(f"              - {a}")
        if refs["changelog"]:
            print(f"  Changelog:  {refs['changelog'][0]}")
        if refs["other"]:
            print(f"  Other refs: {len(refs['other'])}")

    if show_cves:
        n = count_cves(name, api_key)
        if n is not None:
            print(f"  Known CVEs: {n}")
        time.sleep(0.6)  # rate-limit courtesy


def main():
    p = argparse.ArgumentParser(description="Search NVD CPE Dictionary (enriched)")
    p.add_argument("--keyword", "-k")
    p.add_argument("--vendor", "-v")
    p.add_argument("--product", "-p")
    p.add_argument("--cpe")
    p.add_argument("--limit", "-n", type=int, default=50)
    p.add_argument("--details", "-d", action="store_true",
                   help="Show titles, refs, repo links, advisories")
    p.add_argument("--cves", action="store_true",
                   help="Also query NVD for number of known CVEs per CPE")
    p.add_argument("--api-key", default="")
    args = p.parse_args()

    params = {"resultsPerPage": min(args.limit, 500)}
    if args.cpe:
        params["cpeMatchString"] = args.cpe
    elif args.keyword:
        params["keywordSearch"] = args.keyword
    elif args.vendor and args.product:
        params["cpeMatchString"] = f"cpe:2.3:*:{args.vendor}:{args.product}:*"
    elif args.vendor:
        params["cpeMatchString"] = f"cpe:2.3:*:{args.vendor}:*"
    elif args.product:
        params["keywordSearch"] = args.product
    else:
        p.print_help()
        return

    data = http_get(NVD_CPE_API, params, args.api_key)
    if not data:
        return

    total = data.get("totalResults", 0)
    products = data.get("products", [])
    print(f"\n{total} results (showing {len(products)})")
    print("=" * 78)

    for prod in products:
        print_product(prod, args.details, args.cves, args.api_key)

    print()


if __name__ == "__main__":
    main()