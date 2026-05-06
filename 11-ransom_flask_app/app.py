import csv
import io
import math
import os
import sys
import subprocess
import requests
import markdown
import numpy as np
from collections import defaultdict
from flask import Flask, render_template, jsonify, request, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-lgr-key-change-in-prod")
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def load_csv(filename):
    filepath = os.path.join(DATA_DIR, filename)
    rows = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed = {}
            for key, val in row.items():
                try:
                    num = float(val)
                    parsed[key] = val if math.isinf(num) or math.isnan(num) else num
                except (ValueError, TypeError):
                    parsed[key] = val
            rows.append(parsed)
    return rows


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/category-or")
def category_or():
    return render_template("category_or.html")


@app.route("/api/category-or")
def api_category_or():
    data = load_csv("A1_category_OR_universe.csv")
    return jsonify(data)


@app.route("/vendor-or")
def vendor_or():
    return render_template("vendor_or.html")


@app.route("/api/vendor-or")
def api_vendor_or():
    data = load_csv("A2_vendor_OR_universe.csv")
    return jsonify(data)


@app.route("/product-or")
def product_or():
    return render_template("product_or.html")


@app.route("/api/product-or")
def api_product_or():
    data = load_csv("A3_product_OR_universe.csv")
    return jsonify(data)


@app.route("/group-category-or")
def group_category_or():
    return render_template("group_category_or.html")


@app.route("/api/group-category-or")
def api_group_category_or():
    data = load_csv("A5_group_category_OR.csv")
    return jsonify(data)


@app.route("/group-vendor-or")
def group_vendor_or():
    return render_template("group_vendor_or.html")


@app.route("/api/group-vendor-or")
def api_group_vendor_or():
    data = load_csv("A6_group_vendor_OR.csv")
    return jsonify(data)


@app.route("/group-product-or")
def group_product_or():
    return render_template("group_product_or.html")


@app.route("/api/group-product-or")
def api_group_product_or():
    data = load_csv("A7_group_product_OR.csv")
    return jsonify(data)


@app.route("/tech-cve-summary")
def tech_cve_summary():
    return render_template("tech_cve_summary.html")


@app.route("/api/tech-cve-summary")
def api_tech_cve_summary():
    data = load_csv(os.path.join("tech_cve", "tech_cve_summary.csv"))
    return jsonify(data)


# ── Tech CVE Results (server-side pagination for large file) ──

_cve_results_cache = None
_cpe_lookup_tech_cache = None


def _build_cpe_lookup_tech():
    """Build a {(VendorName, Product): (cpe_vendor, cpe_product)} lookup from the tech_cve summary CSV."""
    global _cpe_lookup_tech_cache
    if _cpe_lookup_tech_cache is None:
        summary = load_csv(os.path.join("tech_cve", "tech_cve_summary.csv"))
        _cpe_lookup_tech_cache = {}
        for row in summary:
            key = (row.get("VendorName", ""), row.get("Product", ""))
            _cpe_lookup_tech_cache[key] = (row.get("cpe_vendor", ""), row.get("cpe_product", ""))
    return _cpe_lookup_tech_cache


def _load_cve_results():
    global _cve_results_cache
    if _cve_results_cache is None:
        raw = load_csv(os.path.join("tech_cve", "tech_cve_results.csv"))
        lookup = _build_cpe_lookup_tech()
        for row in raw:
            cpe = lookup.get((row.get("VendorName", ""), row.get("Product", "")), ("", ""))
            row["cpe_vendor"] = cpe[0]
            row["cpe_product"] = cpe[1]
        _cve_results_cache = raw
    return _cve_results_cache


@app.route("/tech-cve-results")
def tech_cve_results():
    return render_template("tech_cve_results.html")


@app.route("/api/tech-cve-results")
def api_tech_cve_results():
    data = _load_cve_results()

    # ── filtering ──
    filtered = data
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        val_lower = val.lower()
        filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    # ── sorting ──
    sort_field = request.args.get("sort_field")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_field:
        reverse = sort_dir == "desc"
        def sort_key(r):
            v = r.get(sort_field, "")
            if isinstance(v, (int, float)):
                return (0, v)
            return (1, str(v).lower())
        filtered = sorted(filtered, key=sort_key, reverse=reverse)

    total = len(filtered)

    # ── pagination ──
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 25))
    size = min(size, 200)
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "data": page_data,
    })


@app.route("/api/tech-cve-results/stats")
def api_tech_cve_results_stats():
    data = _load_cve_results()

    # apply same filters as the main endpoint
    filtered = data
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        val_lower = val.lower()
        filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    total = len(filtered)
    sev_counts = {}
    for r in filtered:
        s = r.get("severity", "")
        if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_counts[s] = sev_counts.get(s, 0) + 1
    products = len(set(
        (r.get("VendorName", ""), r.get("Product", ""))
        for r in filtered
    ))
    return jsonify({
        "total_cves": total,
        "distinct_products": products,
        "critical": sev_counts.get("CRITICAL", 0),
        "high": sev_counts.get("HIGH", 0),
        "medium": sev_counts.get("MEDIUM", 0),
        "low": sev_counts.get("LOW", 0),
    })


# ── Tech CVE Normalized Summary ──

@app.route("/tech-cve-normalized-summary")
def tech_cve_normalized_summary():
    return render_template("tech_cve_normalized_summary.html")


@app.route("/api/tech-cve-normalized-summary")
def api_tech_cve_normalized_summary():
    data = load_csv(os.path.join("tech_cve_normalized", "tech_cve_summary.csv"))
    return jsonify(data)


# ── Tech CVE Normalized Results (server-side pagination for large file) ──

_cve_normalized_results_cache = None
_cpe_lookup_cache = None


def _build_cpe_lookup():
    """Build a {(VendorName, Product): (cpe_vendor, cpe_product)} lookup from the summary CSV."""
    global _cpe_lookup_cache
    if _cpe_lookup_cache is None:
        summary = load_csv(os.path.join("tech_cve_normalized", "tech_cve_summary.csv"))
        _cpe_lookup_cache = {}
        for row in summary:
            key = (row.get("VendorName", ""), row.get("Product", ""))
            _cpe_lookup_cache[key] = (row.get("cpe_vendor", ""), row.get("cpe_product", ""))
    return _cpe_lookup_cache


def _load_cve_normalized_results():
    global _cve_normalized_results_cache
    if _cve_normalized_results_cache is None:
        raw = load_csv(os.path.join("tech_cve_normalized", "tech_cve_results.csv"))
        lookup = _build_cpe_lookup()
        for row in raw:
            cpe = lookup.get((row.get("VendorName", ""), row.get("Product", "")), ("", ""))
            row["cpe_vendor"] = cpe[0]
            row["cpe_product"] = cpe[1]
        _cve_normalized_results_cache = raw
    return _cve_normalized_results_cache


@app.route("/tech-cve-normalized-results")
def tech_cve_normalized_results():
    return render_template("tech_cve_normalized_results.html")


@app.route("/api/tech-cve-normalized-results")
def api_tech_cve_normalized_results():
    data = _load_cve_normalized_results()

    # ── filtering ──
    filtered = data
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        val_lower = val.lower()
        filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    # ── sorting ──
    sort_field = request.args.get("sort_field")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_field:
        reverse = sort_dir == "desc"
        def sort_key(r):
            v = r.get(sort_field, "")
            if isinstance(v, (int, float)):
                return (0, v)
            return (1, str(v).lower())
        filtered = sorted(filtered, key=sort_key, reverse=reverse)

    total = len(filtered)

    # ── pagination ──
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 25))
    size = min(size, 200)
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "data": page_data,
    })


@app.route("/api/tech-cve-normalized-results/stats")
def api_tech_cve_normalized_results_stats():
    data = _load_cve_normalized_results()

    # apply same filters as the main endpoint
    filtered = data
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        val_lower = val.lower()
        filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    total = len(filtered)
    sev_counts = {}
    for r in filtered:
        s = r.get("severity", "")
        if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_counts[s] = sev_counts.get(s, 0) + 1
    products = len(set(
        (r.get("VendorName", ""), r.get("Product", ""))
        for r in filtered
    ))
    return jsonify({
        "total_cves": total,
        "distinct_products": products,
        "critical": sev_counts.get("CRITICAL", 0),
        "high": sev_counts.get("HIGH", 0),
        "medium": sev_counts.get("MEDIUM", 0),
        "low": sev_counts.get("LOW", 0),
    })


# ── All CPEs Normalized (server-side pagination for ~1.6M rows) ──

_all_cpes_cache = None


def _load_all_cpes():
    global _all_cpes_cache
    if _all_cpes_cache is None:
        _all_cpes_cache = load_csv(
            os.path.join("tech_cve_normalized", "all_cpes.csv")
        )
    return _all_cpes_cache


@app.route("/all-cpes-normalized")
def all_cpes_normalized():
    return render_template("all_cpes_normalized.html")


@app.route("/api/all-cpes-normalized")
def api_all_cpes_normalized():
    data = _load_all_cpes()

    # ── filtering ──
    filtered = data
    exact_fields = {"part", "deprecated"}
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        if field in exact_fields:
            filtered = [r for r in filtered if str(r.get(field, "")) == val]
        else:
            val_lower = val.lower()
            filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    # ── sorting ──
    sort_field = request.args.get("sort_field")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_field:
        reverse = sort_dir == "desc"
        def sort_key(r):
            v = r.get(sort_field, "")
            if isinstance(v, (int, float)):
                return (0, v)
            return (1, str(v).lower())
        filtered = sorted(filtered, key=sort_key, reverse=reverse)

    total = len(filtered)

    # ── pagination ──
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 25))
    size = min(size, 200)
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "data": page_data,
    })


@app.route("/api/all-cpes-normalized/stats")
def api_all_cpes_normalized_stats():
    data = _load_all_cpes()

    filtered = data
    exact_fields = {"part", "deprecated"}
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        if field in exact_fields:
            filtered = [r for r in filtered if str(r.get(field, "")) == val]
        else:
            val_lower = val.lower()
            filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    total = len(filtered)
    part_counts = {}
    deprecated_count = 0
    vendors = set()
    products = set()
    for r in filtered:
        p = r.get("part", "")
        if p:
            part_counts[p] = part_counts.get(p, 0) + 1
        if str(r.get("deprecated", "")) == "True":
            deprecated_count += 1
        vendors.add(r.get("vendor", ""))
        products.add((r.get("vendor", ""), r.get("product", "")))

    return jsonify({
        "total": total,
        "distinct_vendors": len(vendors),
        "distinct_products": len(products),
        "part_a": part_counts.get("a", 0),
        "part_h": part_counts.get("h", 0),
        "part_o": part_counts.get("o", 0),
        "deprecated": deprecated_count,
    })


# ── CPE ↔ SWDB Merged ──

@app.route("/cpe-swdb-merged")
def cpe_swdb_merged():
    return render_template("cpe_swdb_merged.html")


@app.route("/api/cpe-swdb-merged")
def api_cpe_swdb_merged():
    data = load_csv(os.path.join("tech_cve_normalized", "cpe_swdb_merged.csv"))
    return jsonify(data)


# ── CVE Summary (Teyyub) ──

@app.route("/cve-summary-teyyub")
def cve_summary_teyyub():
    return render_template("cve_summary_teyyub.html")


@app.route("/api/cve-summary-teyyub")
def api_cve_summary_teyyub():
    data = load_csv(os.path.join("tech_cve", "cve_summary_teyyub.csv"))
    return jsonify(data)


# ── CVE Exposure (join CVE results × installs) ──

_cve_exposure_cache = None


def _parse_install_num(s):
    if not s:
        return 0
    try:
        return int(s.replace(",", "").strip())
    except ValueError:
        return 0


def _load_cve_exposure():
    global _cve_exposure_cache
    if _cve_exposure_cache is not None:
        return _cve_exposure_cache

    # Build installs lookup  (VendorName, Product) → row
    installs = {}
    path = os.path.join(DATA_DIR, "tech_cve", "swdb_universe_installs.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            k = (row["VendorName"], row["Product"])
            if k not in installs:
                installs[k] = row

    # Aggregate CVE results by cve_id
    cve_map = defaultdict(lambda: {
        "products": set(),
        "match_methods": set(),
        "severity": "",
        "base_score": "",
        "published_date": "",
        "description": "",
    })
    cve_path = os.path.join(DATA_DIR, "tech_cve", "tech_cve_results.csv")
    with open(cve_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cid = row["cve_id"]
            cve_map[cid]["products"].add((row["VendorName"], row["Product"]))
            mm = row.get("match_method", "")
            if mm:
                cve_map[cid]["match_methods"].add(mm)
            if not cve_map[cid]["severity"]:
                cve_map[cid]["severity"] = row.get("severity", "")
                cve_map[cid]["base_score"] = row.get("base_score", "")
                cve_map[cid]["published_date"] = row.get("published_date", "")
                cve_map[cid]["description"] = row.get("description", "")

    # Join with installs
    results = []
    for cid, info in cve_map.items():
        total_sites = 0
        total_enterprises = 0
        product_names = []
        for vp in info["products"]:
            product_names.append(f"{vp[0]} – {vp[1]}")
            inst = installs.get(vp)
            if inst:
                total_sites += _parse_install_num(inst.get("Total Sites", "0"))
                total_enterprises += _parse_install_num(inst.get("Total Enterprises", "0"))

        bs = info["base_score"]
        try:
            bs_num = float(bs)
        except (ValueError, TypeError):
            bs_num = None

        results.append({
            "cve_id": cid,
            "severity": info["severity"],
            "base_score": bs_num,
            "published_date": info["published_date"],
            "num_products": len(info["products"]),
            "products": ", ".join(sorted(product_names)),
            "total_sites": total_sites,
            "total_enterprises": total_enterprises,
            "match_method": ", ".join(sorted(info["match_methods"])),
            "description": info["description"],
        })

    _cve_exposure_cache = results
    return _cve_exposure_cache


@app.route("/cve-exposure")
def cve_exposure():
    return render_template("cve_exposure.html")


@app.route("/api/cve-exposure")
def api_cve_exposure():
    data = _load_cve_exposure()

    # filtering
    filtered = data
    numeric_gte_fields = {"total_sites", "total_enterprises", "base_score", "num_products"}
    exact_fields = {"cve_id"}
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        if field in numeric_gte_fields:
            try:
                threshold = float(val)
            except ValueError:
                continue
            filtered = [r for r in filtered if (r.get(field) or 0) >= threshold]
        elif field in exact_fields:
            val_upper = val.strip().upper()
            filtered = [r for r in filtered if str(r.get(field, "")).upper() == val_upper]
        else:
            val_lower = val.lower()
            filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    # sorting
    sort_field = request.args.get("sort_field")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_field:
        reverse = sort_dir == "desc"

        def sort_key(r):
            v = r.get(sort_field, "")
            if isinstance(v, (int, float)) and v is not None:
                return (0, v if v is not None else 0)
            return (1, str(v).lower())

        filtered = sorted(filtered, key=sort_key, reverse=reverse)

    total = len(filtered)

    # pagination
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 25))
    size = min(size, 200)
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({"last_page": last_page, "data": page_data})


@app.route("/api/cve-exposure/stats")
def api_cve_exposure_stats():
    data = _load_cve_exposure()

    # apply same filters as the main endpoint
    filtered = data
    numeric_gte_fields = {"total_sites", "total_enterprises", "base_score", "num_products"}
    exact_fields = {"cve_id"}
    filter_args = {k: v for k, v in request.args.items() if k.startswith("filter_")}
    for key, val in filter_args.items():
        field = key[len("filter_"):]
        if not val:
            continue
        if field in numeric_gte_fields:
            try:
                threshold = float(val)
            except ValueError:
                continue
            filtered = [r for r in filtered if (r.get(field) or 0) >= threshold]
        elif field in exact_fields:
            val_upper = val.strip().upper()
            filtered = [r for r in filtered if str(r.get(field, "")).upper() == val_upper]
        else:
            val_lower = val.lower()
            filtered = [r for r in filtered if val_lower in str(r.get(field, "")).lower()]

    total = len(filtered)
    sev = {}
    max_sites = 0
    max_sites_cve = ""
    sum_sites = 0
    sum_ent = 0
    for r in filtered:
        s = r.get("severity", "")
        if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev[s] = sev.get(s, 0) + 1
        ts = r.get("total_sites", 0)
        sum_sites += ts
        sum_ent += r.get("total_enterprises", 0)
        if ts > max_sites:
            max_sites = ts
            max_sites_cve = r.get("cve_id", "")
    return jsonify({
        "total_cves": total,
        "critical": sev.get("CRITICAL", 0),
        "high": sev.get("HIGH", 0),
        "medium": sev.get("MEDIUM", 0),
        "low": sev.get("LOW", 0),
        "max_sites": max_sites,
        "max_sites_cve": max_sites_cve,
        "avg_sites": round(sum_sites / total) if total else 0,
        "avg_enterprises": round(sum_ent / total) if total else 0,
    })


# ── Complete Rows (v4) ─────────────────────────────────────────────
@app.route("/complete-rows-summary")
def complete_rows_summary():
    return render_template("complete_rows_summary.html")

@app.route("/api/complete-rows-summary")
def api_complete_rows_summary():
    return jsonify(load_csv(os.path.join("complete_rows_data", "tech_cve_summary_v4.csv")))

@app.route("/complete-rows-results")
def complete_rows_results():
    return render_template("complete_rows_results.html")

@app.route("/api/complete-rows-results")
def api_complete_rows_results():
    return jsonify(load_csv(os.path.join("complete_rows_data", "tech_cve_results_v4.csv")))


# ── CVE v4 ─────────────────────────────────────────────────────────
@app.route("/cve-v4-summary")
def cve_v4_summary():
    return render_template("cve_v4_summary.html")

@app.route("/api/cve-v4-summary")
def api_cve_v4_summary():
    return jsonify(load_csv(os.path.join("cve_v4", "tech_cve_summary_v4.csv")))

@app.route("/cve-v4-results")
def cve_v4_results():
    return render_template("cve_v4_results.html")

@app.route("/api/cve-v4-results")
def api_cve_v4_results():
    return jsonify(load_csv(os.path.join("cve_v4", "tech_cve_results_v4.csv")))

@app.route("/ground-truth-200")
def ground_truth_200():
    return render_template("ground_truth_200.html")


@app.route("/ground-truth-200/methodology")
def ground_truth_200_methodology():
    md_path = os.path.join(os.path.dirname(__file__), "ground_truth_methodology.md")
    with open(md_path, encoding="utf-8") as f:
        md_text = f.read()
    html_content = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    return render_template(
        "ransom_leaks.html",
        content=html_content,
        page_title="Ground Truth — Methodology",
    )


# ── Test Single Product (live SWDB→CPE→CVE pipeline runner) ───────
@app.route("/test-single-product", methods=["GET", "POST"])
def test_single_product():
    output = None
    error = None
    vendor = (request.values.get("vendor") or "").strip()
    product = (request.values.get("product") or "").strip()
    try:
        max_cves = int(request.values.get("max_cves") or 10)
    except ValueError:
        max_cves = 10
    max_cves = max(1, min(max_cves, 100))
    skip_tier23 = bool(request.values.get("skip_tier23"))

    if request.method == "POST" and vendor and product:
        script = os.path.join(os.path.dirname(__file__), "cpe_cve_process.py")
        cmd = [sys.executable, script, vendor, product, "--max-cves", str(max_cves)]
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key:
            cmd += ["--api-key", api_key]
        if skip_tier23:
            cmd.append("--no-tier23")
        try:
            proc = subprocess.run(
                cmd,
                cwd=os.path.dirname(__file__),
                capture_output=True,
                text=True,
                timeout=180,
            )
            output = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
            if proc.returncode != 0:
                error = f"Process exited with code {proc.returncode}"
        except subprocess.TimeoutExpired:
            error = "Pipeline timed out after 180s. Try --no-tier23 or fewer CVEs."
        except Exception as e:
            error = f"Failed to run pipeline: {e}"

    return render_template(
        "test_single_product.html",
        vendor=vendor,
        product=product,
        max_cves=max_cves,
        skip_tier23=skip_tier23,
        output=output,
        error=error,
    )


_GT200_FILE = "cve_v4_summary_random_200_ground_truth.csv"
_gt200_cache = None  # list[dict] including a stable _row_idx
_gt200_fieldnames = None  # list[str], CSV header order (with handcheck appended)


def _gt200_normalize_bool(v):
    """Coerce a value to canonical 'TRUE' / 'FALSE' / '' string."""
    if v is True:
        return "TRUE"
    if v is False:
        return "FALSE"
    if v is None:
        return ""
    s = str(v).strip().upper()
    if s in ("TRUE", "T", "1", "YES", "Y"):
        return "TRUE"
    if s in ("FALSE", "F", "0", "NO", "N"):
        return "FALSE"
    return ""


def _load_gt200():
    """Load the ground-truth CSV with an editable `handcheck` column.

    Each row gets an internal `_row_idx` (its 0-based position in the file)
    used by the update endpoint as a stable identifier.
    """
    global _gt200_cache, _gt200_fieldnames
    if _gt200_cache is not None:
        return _gt200_cache

    path = os.path.join(DATA_DIR, _GT200_FILE)
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        if "handcheck" not in fieldnames:
            fieldnames.append("handcheck")
        for i, row in enumerate(reader):
            row.setdefault("handcheck", "False")
            row["is_correct_match"] = _gt200_normalize_bool(row.get("is_correct_match")) or "FALSE"
            row["handcheck"] = _gt200_normalize_bool(row.get("handcheck")) or "FALSE"
            row["_row_idx"] = i
            rows.append(row)

    _gt200_cache = rows
    _gt200_fieldnames = fieldnames
    return _gt200_cache


def _save_gt200():
    """Persist the current cache back to disk, preserving header order."""
    if _gt200_cache is None or _gt200_fieldnames is None:
        return
    path = os.path.join(DATA_DIR, _GT200_FILE)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_gt200_fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in _gt200_cache:
            writer.writerow({k: row.get(k, "") for k in _gt200_fieldnames})


@app.route("/api/ground-truth-200")
def api_ground_truth_200():
    return jsonify(_load_gt200())


@app.route("/api/ground-truth-200/update", methods=["POST"])
def api_ground_truth_200_update():
    """Mark a single row's is_correct_match (and flip handcheck=True).

    Body JSON: {"row_idx": int, "is_correct_match": bool|str}
    """
    payload = request.get_json(silent=True) or {}
    try:
        idx = int(payload.get("row_idx"))
    except (TypeError, ValueError):
        return jsonify({"error": "row_idx is required and must be an integer"}), 400
    new_val = _gt200_normalize_bool(payload.get("is_correct_match"))
    if new_val not in ("TRUE", "FALSE"):
        return jsonify({"error": "is_correct_match must be true or false"}), 400

    rows = _load_gt200()
    target = next((r for r in rows if r.get("_row_idx") == idx), None)
    if target is None:
        return jsonify({"error": "row not found"}), 404

    target["is_correct_match"] = new_val
    target["handcheck"] = "TRUE"
    _save_gt200()

    return jsonify({
        "ok": True,
        "row_idx": idx,
        "is_correct_match": new_val,
        "handcheck": "TRUE",
    })


# ── CPE Lookup (NVD API proxy) ─────────────────────────────────────
NVD_API_KEY = os.environ.get("NVD_API_KEY", "983cba50-1471-466c-a5cc-567621fcab31")
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "codeberg.org")

def _classify_ref(url):
    u = url.lower()
    for host in REPO_HOSTS:
        if host in u:
            return "repo"
    if any(k in u for k in ("advisor", "cve", "security", "bulletin")):
        return "advisory"
    if any(k in u for k in ("changelog", "release", "commit", "tag")):
        return "changelog"
    return "other"

def _repo_base_url(url):
    """Trim a repo URL to scheme://host/owner/repo (drop /releases, /issues, etc.)."""
    from urllib.parse import urlparse
    p = urlparse(url)
    segs = [s for s in p.path.split("/") if s]
    base = "/".join(segs[:2]) if len(segs) >= 2 else "/".join(segs)
    return f"{p.scheme}://{p.netloc}/{base}" if base else url

def _extract_refs(refs):
    out = {"repo": [], "advisory": [], "changelog": [], "vendor": [], "other": []}
    seen_repos = set()
    for ref in refs or []:
        url = ref.get("ref", "")
        declared = (ref.get("type") or "").lower()
        kind = _classify_ref(url)
        if declared == "vendor" and kind == "other":
            kind = "vendor"
        if kind == "repo":
            short = _repo_base_url(url)
            if short not in seen_repos:
                seen_repos.add(short)
                out["repo"].append(short)
        else:
            out.setdefault(kind, []).append(url)
    return out

def _pick_title(titles):
    if not titles:
        return ""
    for t in titles:
        if t.get("lang") == "en":
            return t.get("title", "")
    return titles[0].get("title", "")

@app.route("/cpe-lookup")
def cpe_lookup():
    return render_template("cpe_lookup.html")

@app.route("/api/cpe-lookup")
def api_cpe_lookup():
    keyword = request.args.get("keyword", "").strip()
    vendor  = request.args.get("vendor", "").strip()
    product = request.args.get("product", "").strip()
    cpe     = request.args.get("cpe", "").strip()
    limit   = min(int(request.args.get("limit", 50)), 500)

    params = {"resultsPerPage": limit}
    desc = ""

    if cpe:
        params["cpeMatchString"] = cpe
        desc = f"cpeMatchString = {cpe}"
    elif keyword:
        params["keywordSearch"] = keyword
        desc = f"keywordSearch = {keyword}"
    elif vendor and product:
        ms = f"cpe:2.3:*:{vendor}:{product}:*"
        params["cpeMatchString"] = ms
        desc = f"cpeMatchString = {ms}"
    elif vendor:
        ms = f"cpe:2.3:*:{vendor}:*"
        params["cpeMatchString"] = ms
        desc = f"cpeMatchString = {ms}"
    else:
        return jsonify({"error": "Provide keyword, vendor, or CPE match string."})

    try:
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        r = requests.get(NVD_CPE_API, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as exc:
        return jsonify({"error": f"NVD API error: {exc}"}), 502

    total = data.get("totalResults", 0)
    products = data.get("products", [])

    rows = []
    for p in products:
        cpe_obj = p.get("cpe", {})
        name = cpe_obj.get("cpeName", "")
        parts = name.split(":")
        titles = cpe_obj.get("titles", [])
        title = _pick_title(titles)
        refs = _extract_refs(cpe_obj.get("refs"))
        dep_by = [d.get("cpeName", "") for d in cpe_obj.get("deprecatedBy", [])]

        rows.append({
            "cpeName": name,
            "part": parts[2] if len(parts) > 2 else "",
            "vendor": parts[3] if len(parts) > 3 else "",
            "product": parts[4] if len(parts) > 4 else "",
            "version": parts[5] if len(parts) > 5 else "",
            "title": title,
            "deprecated": cpe_obj.get("deprecated", False),
            "deprecatedBy": ", ".join(dep_by) if dep_by else "",
            "created": (cpe_obj.get("created", "") or "")[:10],
            "lastModified": (cpe_obj.get("lastModified", "") or "")[:10],
            "repoUrls": refs.get("repo", []),
            "advisoryUrls": refs.get("advisory", []),
            "changelogUrls": refs.get("changelog", []),
            "vendorUrls": refs.get("vendor", []),
            "otherUrls": refs.get("other", []),
            "totalRefs": sum(len(v) for v in refs.values()),
        })

    return jsonify({
        "totalResults": total,
        "queryDescription": desc,
        "results": rows,
    })


# ── CVE Lookup (NVD API proxy) ─────────────────────────────────────
@app.route("/cve-lookup")
def cve_lookup():
    return render_template("cve_lookup.html")

@app.route("/api/cve-lookup")
def api_cve_lookup():
    keyword  = request.args.get("keyword", "").strip()
    cve_id   = request.args.get("cve_id", "").strip()
    cpe      = request.args.get("cpe", "").strip()
    severity = request.args.get("severity", "").strip()
    pub_from = request.args.get("pub_from", "").strip()
    pub_to   = request.args.get("pub_to", "").strip()
    has_kev  = request.args.get("kev", "").strip()
    limit    = min(int(request.args.get("limit", 50)), 2000)

    params = {"resultsPerPage": limit}
    desc = ""

    if cve_id:
        params["cveId"] = cve_id
        desc = f"cveId = {cve_id}"
    elif cpe:
        params["virtualMatchString"] = cpe
        desc = f"virtualMatchString = {cpe}"
    elif keyword:
        params["keywordSearch"] = keyword
        desc = f"keywordSearch = {keyword}"
    else:
        return jsonify({"error": "Provide a CVE ID, keyword, or CPE match string."})

    if severity:
        params["cvssV3Severity"] = severity
        desc += f" | cvssV3Severity = {severity}"
    if pub_from:
        params["pubStartDate"] = f"{pub_from}T00:00:00.000"
        desc += f" | from {pub_from}"
    if pub_to:
        params["pubEndDate"] = f"{pub_to}T23:59:59.999"
        desc += f" | to {pub_to}"
    if has_kev:
        params["hasKev"] = ""
        desc += " | KEV only"

    try:
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as exc:
        return jsonify({"error": f"NVD API error: {exc}"}), 502

    total = data.get("totalResults", 0)
    vulns = data.get("vulnerabilities", [])

    rows = []
    for v in vulns:
        cve = v.get("cve", {})
        cid = cve.get("id", "")
        descs = cve.get("descriptions", [])
        en_desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score, sev = "", ""
        for ver in ["cvssMetricV31", "cvssMetricV30"]:
            if ver in metrics and metrics[ver]:
                cvss = metrics[ver][0].get("cvssData", {})
                score = cvss.get("baseScore", "")
                sev = cvss.get("baseSeverity", "")
                break
        if not sev and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss2 = metrics["cvssMetricV2"][0].get("cvssData", {})
            score = cvss2.get("baseScore", "")
            sev = metrics["cvssMetricV2"][0].get("baseSeverity", "")

        published = (cve.get("published", "") or "")[:10]

        vendors_set, products_set = set(), set()
        cpe_list = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        cpe_list.append(criteria)
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendors_set.add(parts[3])
                        products_set.add(parts[4])

        is_kev = bool(cve.get("cisaExploitabilityScore")
                       or cve.get("cisaActionDue")
                       or cve.get("cisaRequiredAction"))

        rows.append({
            "cve_id": cid,
            "base_score": score,
            "severity": sev,
            "published": published,
            "kev": is_kev,
            "vendors": ", ".join(sorted(vendors_set)),
            "products": ", ".join(sorted(products_set)),
            "cpes": cpe_list,
            "description": en_desc,
        })

    return jsonify({
        "totalResults": total,
        "queryDescription": desc,
        "results": rows,
    })


@app.route("/leaks")
def leaks():
    md_path = os.path.join(os.path.dirname(__file__), "ransom_leaks.md")
    with open(md_path, encoding="utf-8") as f:
        md_text = f.read()
    html_content = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    return render_template("ransom_leaks.html", content=html_content)


# ── Black Basta chat leaks (server-side pagination for ~265K records) ──

import re as _re

_blackbasta_cache = None
_BB_FIELD_RE = _re.compile(
    r"^\s*(timestamp|chat_id|sender_alias|message)\s*:\s*(.*?)\s*$"
)


def _load_blackbasta_chats():
    """Parse the pseudo-JSON Black Basta chat dump into a list of dicts.

    The file is not valid JSON: keys/values are unquoted, and `message`
    values may span multiple lines. Each record is delimited by lines
    containing only `{` and `}` (or `},`).
    """
    global _blackbasta_cache
    if _blackbasta_cache is not None:
        return _blackbasta_cache

    path = os.path.join(DATA_DIR, "leaks", "blackbasta_chats.json")
    records = []
    cur = None
    field = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            stripped = raw.strip()
            if stripped == "{":
                cur = {"timestamp": "", "chat_id": "", "sender_alias": "", "message": ""}
                field = None
                continue
            if stripped in ("}", "},"):
                if cur is not None:
                    # trim trailing comma left on message tail line
                    if cur["message"].endswith(","):
                        cur["message"] = cur["message"][:-1]
                    records.append(cur)
                cur = None
                field = None
                continue
            if cur is None:
                continue
            m = _BB_FIELD_RE.match(raw)
            if m and m.group(1) in ("timestamp", "chat_id", "sender_alias") and field != "message":
                field = m.group(1)
                val = m.group(2)
                if val.endswith(","):
                    val = val[:-1]
                cur[field] = val
            elif m and m.group(1) == "message":
                field = "message"
                cur["message"] = m.group(2)
            else:
                # continuation of a multi-line message
                if field == "message":
                    cur["message"] += "\n" + raw

    # Drop empty / whitespace-only messages — they add noise to the leaks view.
    records = [r for r in records if (r.get("message") or "").strip()]

    _blackbasta_cache = records
    return _blackbasta_cache


def _filter_blackbasta(rows):
    """Apply ?filter_<field>= query params (substring, case-insensitive)."""
    args = request.args
    q = (args.get("filter_q") or "").strip().lower()
    sender = (args.get("filter_sender_alias") or "").strip().lower()
    chat = (args.get("filter_chat_id") or "").strip().lower()
    msg = (args.get("filter_message") or "").strip().lower()
    date_from = (args.get("filter_date_from") or "").strip()
    date_to = (args.get("filter_date_to") or "").strip()

    out = rows
    if q:
        out = [r for r in out if
               q in r["message"].lower()
               or q in r["sender_alias"].lower()
               or q in r["chat_id"].lower()]
    if sender:
        out = [r for r in out if sender in r["sender_alias"].lower()]
    if chat:
        out = [r for r in out if chat in r["chat_id"].lower()]
    if msg:
        out = [r for r in out if msg in r["message"].lower()]
    if date_from:
        out = [r for r in out if r["timestamp"] >= date_from]
    if date_to:
        out = [r for r in out if r["timestamp"] <= date_to]
    return out


@app.route("/leaks/blackbasta")
def blackbasta_leaks():
    return render_template("blackbasta_leaks.html")


@app.route("/api/leaks/blackbasta")
def api_blackbasta_leaks():
    data = _load_blackbasta_chats()
    filtered = _filter_blackbasta(data)

    # sorting
    sort_field = request.args.get("sort_field", "timestamp")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_field in ("timestamp", "chat_id", "sender_alias", "message"):
        filtered = sorted(
            filtered,
            key=lambda r: r.get(sort_field, "").lower() if isinstance(r.get(sort_field), str) else r.get(sort_field, ""),
            reverse=(sort_dir == "desc"),
        )

    total = len(filtered)
    page = max(1, int(request.args.get("page", 1)))
    size = min(200, max(1, int(request.args.get("size", 50))))
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "total": total,
        "data": page_data,
    })


@app.route("/api/leaks/blackbasta/stats")
def api_blackbasta_leaks_stats():
    data = _load_blackbasta_chats()
    filtered = _filter_blackbasta(data)

    senders = set()
    chats = set()
    min_ts = None
    max_ts = None
    sender_counts = defaultdict(int)
    chat_counts = defaultdict(int)
    for r in filtered:
        senders.add(r["sender_alias"])
        chats.add(r["chat_id"])
        sender_counts[r["sender_alias"]] += 1
        chat_counts[r["chat_id"]] += 1
        ts = r["timestamp"]
        if ts:
            if min_ts is None or ts < min_ts:
                min_ts = ts
            if max_ts is None or ts > max_ts:
                max_ts = ts

    top_senders = sorted(sender_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_chats = sorted(chat_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return jsonify({
        "total_messages": len(filtered),
        "distinct_senders": len(senders),
        "distinct_chats": len(chats),
        "earliest": min_ts or "",
        "latest": max_ts or "",
        "top_senders": [{"sender_alias": s, "count": c} for s, c in top_senders],
        "top_chats": [{"chat_id": s, "count": c} for s, c in top_chats],
    })


@app.route("/api/leaks/blackbasta/thread")
def api_blackbasta_thread():
    """Return the conversation context around a given message.

    Query params:
        chat_id   (required) — the room/chat identifier
        timestamp (required) — exact timestamp of the anchor message
        before    (optional, default 15) — messages before the anchor
        after     (optional, default 30) — messages after the anchor
    Returns the contiguous slice of messages from the same chat_id sorted
    by timestamp, plus the index of the anchor message in `data`.
    """
    chat_id = (request.args.get("chat_id") or "").strip()
    timestamp = (request.args.get("timestamp") or "").strip()
    if not chat_id or not timestamp:
        return jsonify({"error": "chat_id and timestamp are required"}), 400
    try:
        before = max(0, min(200, int(request.args.get("before", 15))))
        after = max(0, min(500, int(request.args.get("after", 30))))
    except (TypeError, ValueError):
        before, after = 15, 30

    chat_msgs = [r for r in _load_blackbasta_chats() if r["chat_id"] == chat_id]
    chat_msgs.sort(key=lambda r: r["timestamp"])

    # locate anchor (first exact match on timestamp; fall back to nearest)
    anchor_idx = None
    for i, r in enumerate(chat_msgs):
        if r["timestamp"] == timestamp:
            anchor_idx = i
            break
    if anchor_idx is None:
        # nearest by lexicographic timestamp comparison
        for i, r in enumerate(chat_msgs):
            if r["timestamp"] >= timestamp:
                anchor_idx = i
                break
        if anchor_idx is None:
            anchor_idx = max(0, len(chat_msgs) - 1)

    start = max(0, anchor_idx - before)
    end = min(len(chat_msgs), anchor_idx + after + 1)
    slice_ = chat_msgs[start:end]

    return jsonify({
        "chat_id": chat_id,
        "anchor_timestamp": timestamp,
        "anchor_index": anchor_idx - start,
        "total_in_chat": len(chat_msgs),
        "data": slice_,
    })


# ── Black Basta product hits (CSV: vendor x product -> linked chat msg ids) ──

_blackbasta_hits_cache = None
_blackbasta_chat_index = None  # { "chat_id@timestamp" -> message record }


def _load_blackbasta_product_hits():
    """Load data/leaks/blackbasta_product_hits.csv into a list of dicts.

    CSV cols: vendor, product, count, n_unique_msgs, variants_hit, msg_ids
    `msg_ids` is a pipe-delimited string of `chat_id@timestamp` keys
    referencing messages in blackbasta_chats.json.
    """
    global _blackbasta_hits_cache
    if _blackbasta_hits_cache is not None:
        return _blackbasta_hits_cache

    path = os.path.join(DATA_DIR, "leaks", "blackbasta_product_hits.csv")
    rows = []
    csv.field_size_limit(sys.maxsize)
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                cnt = int(row.get("count") or 0)
            except (TypeError, ValueError):
                cnt = 0
            try:
                n_unique = int(row.get("n_unique_msgs") or 0)
            except (TypeError, ValueError):
                n_unique = 0
            ids_raw = (row.get("msg_ids") or "").strip()
            n_ids = ids_raw.count("|") + 1 if ids_raw else 0
            rows.append({
                "vendor": (row.get("vendor") or "").strip(),
                "product": (row.get("product") or "").strip(),
                "count": cnt,
                "n_unique_msgs": n_unique,
                "variants_hit": (row.get("variants_hit") or "").strip(),
                "n_msg_ids": n_ids,
                "_msg_ids_raw": ids_raw,  # kept internal, stripped from API
            })
    _blackbasta_hits_cache = rows
    return rows


def _get_blackbasta_chat_index():
    """Build a lookup dict mapping `chat_id@timestamp` -> chat message dict."""
    global _blackbasta_chat_index
    if _blackbasta_chat_index is not None:
        return _blackbasta_chat_index
    idx = {}
    for r in _load_blackbasta_chats():
        key = (r.get("chat_id") or "") + "@" + (r.get("timestamp") or "")
        # if duplicate keys, keep the first (rare)
        if key not in idx:
            idx[key] = r
    _blackbasta_chat_index = idx
    return idx


def _filter_blackbasta_hits(rows):
    args = request.args
    vendor = (args.get("filter_vendor") or "").strip().lower()
    product = (args.get("filter_product") or "").strip().lower()
    variants = (args.get("filter_variants") or "").strip().lower()
    q = (args.get("filter_q") or "").strip().lower()
    min_count = (args.get("filter_min_count") or "").strip()

    out = rows
    if vendor:
        out = [r for r in out if vendor in r["vendor"].lower()]
    if product:
        out = [r for r in out if product in r["product"].lower()]
    if variants:
        out = [r for r in out if variants in r["variants_hit"].lower()]
    if q:
        out = [r for r in out if
               q in r["vendor"].lower()
               or q in r["product"].lower()
               or q in r["variants_hit"].lower()]
    if min_count:
        try:
            mc = int(min_count)
            out = [r for r in out if r["count"] >= mc]
        except ValueError:
            pass
    return out


def _strip_internal(rows):
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]


@app.route("/leaks/blackbasta-product-hits")
def blackbasta_product_hits():
    return render_template("blackbasta_product_hits.html")


@app.route("/api/leaks/blackbasta-product-hits")
def api_blackbasta_product_hits():
    data = _load_blackbasta_product_hits()
    filtered = _filter_blackbasta_hits(data)

    sort_field = request.args.get("sort_field", "count")
    sort_dir = request.args.get("sort_dir", "desc")
    if sort_field in ("vendor", "product", "count", "n_unique_msgs", "variants_hit", "n_msg_ids"):
        def _key(r):
            v = r.get(sort_field, "")
            if isinstance(v, str):
                return v.lower()
            return v
        filtered = sorted(filtered, key=_key, reverse=(sort_dir == "desc"))

    total = len(filtered)
    page = max(1, int(request.args.get("page", 1)))
    size = min(200, max(1, int(request.args.get("size", 50))))
    start = (page - 1) * size
    page_data = _strip_internal(filtered[start:start + size])
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "total": total,
        "data": page_data,
    })


@app.route("/api/leaks/blackbasta-product-hits/stats")
def api_blackbasta_product_hits_stats():
    data = _load_blackbasta_product_hits()
    filtered = _filter_blackbasta_hits(data)

    total_rows = len(filtered)
    vendors = set()
    products = set()
    total_count = 0
    total_unique = 0
    vendor_counts = defaultdict(int)
    product_counts = defaultdict(int)
    variants_counts = defaultdict(int)
    for r in filtered:
        vendors.add(r["vendor"])
        products.add(r["product"])
        total_count += r["count"]
        total_unique += r["n_unique_msgs"]
        vendor_counts[r["vendor"]] += r["count"]
        product_counts[r["product"]] += r["count"]
        for v in (r["variants_hit"] or "").split("|"):
            v = v.strip()
            if v:
                variants_counts[v] += r["count"]

    top_vendors = sorted(vendor_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_products = sorted(product_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_variants = sorted(variants_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return jsonify({
        "total_rows": total_rows,
        "distinct_vendors": len(vendors),
        "distinct_products": len(products),
        "sum_count": total_count,
        "sum_unique_msgs": total_unique,
        "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
        "top_products": [{"product": v, "count": c} for v, c in top_products],
        "top_variants": [{"variant": v, "count": c} for v, c in top_variants],
    })


@app.route("/api/leaks/blackbasta-product-hits/messages")
def api_blackbasta_product_hits_messages():
    """Return the actual chat messages referenced by a vendor+product row.

    Query params:
      vendor (required), product (required)
      page (default 1), size (default 25, max 200)
      msg_q (optional substring filter on message text)
    """
    vendor = (request.args.get("vendor") or "").strip()
    product = (request.args.get("product") or "").strip()
    msg_q = (request.args.get("msg_q") or "").strip().lower()

    rows = _load_blackbasta_product_hits()
    target = None
    for r in rows:
        if r["vendor"] == vendor and r["product"] == product:
            target = r
            break
    if target is None:
        return jsonify({"error": "not found", "data": [], "last_page": 1, "total": 0}), 404

    ids_raw = target.get("_msg_ids_raw") or ""
    keys = [k for k in ids_raw.split("|") if k]

    idx = _get_blackbasta_chat_index()
    msgs = []
    seen = set()
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        rec = idx.get(k)
        if rec is None:
            # fallback: parse the key for display even if no message body
            at = k.rfind("@")
            if at != -1:
                msgs.append({
                    "key": k,
                    "chat_id": k[:at],
                    "timestamp": k[at + 1:],
                    "sender_alias": "",
                    "message": "(message not found in chats dump)",
                })
            continue
        msgs.append({
            "key": k,
            "chat_id": rec.get("chat_id", ""),
            "timestamp": rec.get("timestamp", ""),
            "sender_alias": rec.get("sender_alias", ""),
            "message": rec.get("message", ""),
        })

    if msg_q:
        msgs = [m for m in msgs if msg_q in m["message"].lower()]

    msgs.sort(key=lambda m: m["timestamp"])

    total = len(msgs)
    page = max(1, int(request.args.get("page", 1)))
    size = min(200, max(1, int(request.args.get("size", 25))))
    start = (page - 1) * size
    page_data = msgs[start:start + size]
    last_page = max(1, math.ceil(total / size)) if total else 1

    return jsonify({
        "vendor": vendor,
        "product": product,
        "total": total,
        "last_page": last_page,
        "data": page_data,
    })


# ── Black Basta websites (CSV: domain mentions extracted from chats) ──

_blackbasta_websites_cache = None

# Common multi-part public suffixes so e.g. "foo.co.uk" still counts as primary.
_MULTI_PART_TLDS = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk", "ltd.uk", "plc.uk", "me.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.tw", "com.sg",
    "com.my", "com.ph", "com.pk", "com.sa", "com.eg", "com.co", "com.ve",
    "co.in", "co.kr", "co.za", "co.nz", "co.il", "co.id", "co.th",
    "edu.cn", "gov.cn", "org.cn", "net.cn",
}


def _is_primary_domain(domain: str) -> bool:
    """Return True if `domain` is a registrable / primary domain (no subdomain).

    Heuristic: domains with 2 labels are primary (foo.com). Domains with 3 labels
    where the trailing two form a known multi-part TLD are also primary
    (foo.co.uk). Anything else (mail.foo.com, www.foo.co.uk, …) is a subdomain.
    """
    if not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    if not d or " " in d:
        return False
    parts = d.split(".")
    if len(parts) < 2:
        return False
    if len(parts) == 2:
        return True
    if len(parts) == 3 and ".".join(parts[-2:]) in _MULTI_PART_TLDS:
        return True
    return False


def _load_blackbasta_websites():
    """Load data/leaks/blackbasta_websites.csv into a list of dicts.

    CSV cols: domain, hacked, count, n_unique_msgs, n_unique_senders,
              n_unique_chats, first_seen, last_seen, had_scheme, senders,
              sample_full_urls, msg_ids
    """
    global _blackbasta_websites_cache
    if _blackbasta_websites_cache is not None:
        return _blackbasta_websites_cache

    path = os.path.join(DATA_DIR, "leaks", "blackbasta_websites.csv")
    rows = []
    csv.field_size_limit(sys.maxsize)

    def _to_int(v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    def _to_bool(v):
        return str(v).strip().lower() in ("true", "1", "yes", "y", "t")

    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            domain = (row.get("domain") or "").strip().lower()
            ids_raw = (row.get("msg_ids") or "").strip()
            n_ids = ids_raw.count("|") + 1 if ids_raw else 0
            rows.append({
                "domain": domain,
                "hacked": _to_bool(row.get("hacked")),
                "count": _to_int(row.get("count")),
                "n_unique_msgs": _to_int(row.get("n_unique_msgs")),
                "n_unique_senders": _to_int(row.get("n_unique_senders")),
                "n_unique_chats": _to_int(row.get("n_unique_chats")),
                "first_seen": (row.get("first_seen") or "").strip(),
                "last_seen": (row.get("last_seen") or "").strip(),
                "had_scheme": _to_bool(row.get("had_scheme")),
                "senders": (row.get("senders") or "").strip(),
                "sample_full_urls": (row.get("sample_full_urls") or "").strip(),
                "n_msg_ids": n_ids,
                "is_primary": _is_primary_domain(domain),
                "_msg_ids_raw": ids_raw,
            })

    _blackbasta_websites_cache = rows
    return rows


def _filter_blackbasta_websites(rows):
    args = request.args
    q = (args.get("filter_q") or "").strip().lower()
    domain = (args.get("filter_domain") or "").strip().lower()
    hacked = (args.get("filter_hacked") or "").strip().lower()
    only_primary = (args.get("filter_only_primary") or "").strip().lower() in ("1", "true", "yes", "on")
    min_count = (args.get("filter_min_count") or "").strip()

    out = rows
    if only_primary:
        out = [r for r in out if r["is_primary"]]
    if q:
        out = [r for r in out if
               q in r["domain"]
               or q in r["senders"].lower()
               or q in r["sample_full_urls"].lower()]
    if domain:
        out = [r for r in out if domain in r["domain"]]
    if hacked in ("true", "1", "yes"):
        out = [r for r in out if r["hacked"]]
    elif hacked in ("false", "0", "no"):
        out = [r for r in out if not r["hacked"]]
    if min_count:
        try:
            mc = int(min_count)
            out = [r for r in out if r["count"] >= mc]
        except (TypeError, ValueError):
            pass
    return out


def _strip_internal_websites(rows):
    out = []
    for r in rows:
        out.append({k: v for k, v in r.items() if not k.startswith("_")})
    return out


@app.route("/leaks/blackbasta-websites")
def blackbasta_websites():
    return render_template("blackbasta_websites.html")


@app.route("/api/leaks/blackbasta-websites")
def api_blackbasta_websites():
    rows = _load_blackbasta_websites()
    filtered = _filter_blackbasta_websites(rows)

    sort_field = request.args.get("sort_field", "count")
    sort_dir = request.args.get("sort_dir", "desc")
    sortable = {
        "domain", "hacked", "count", "n_unique_msgs", "n_unique_senders",
        "n_unique_chats", "first_seen", "last_seen", "n_msg_ids", "is_primary",
    }
    if sort_field in sortable:
        filtered = sorted(
            filtered,
            key=lambda r: (r.get(sort_field) is None, r.get(sort_field)
                           if not isinstance(r.get(sort_field), str)
                           else r.get(sort_field).lower()),
            reverse=(sort_dir == "desc"),
        )

    total = len(filtered)
    page = max(1, int(request.args.get("page", 1)))
    size = min(200, max(1, int(request.args.get("size", 50))))
    start = (page - 1) * size
    page_data = _strip_internal_websites(filtered[start:start + size])
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "total": total,
        "data": page_data,
    })


@app.route("/api/leaks/blackbasta-websites/stats")
def api_blackbasta_websites_stats():
    rows = _load_blackbasta_websites()
    filtered = _filter_blackbasta_websites(rows)

    sum_count = sum(r["count"] for r in filtered)
    sum_unique = sum(r["n_unique_msgs"] for r in filtered)
    n_hacked = sum(1 for r in filtered if r["hacked"])
    n_primary = sum(1 for r in filtered if r["is_primary"])

    top_domains = sorted(filtered, key=lambda r: r["count"], reverse=True)[:10]
    top_primary = sorted(
        [r for r in filtered if r["is_primary"]],
        key=lambda r: r["count"], reverse=True
    )[:10]

    return jsonify({
        "total_rows": len(filtered),
        "sum_count": sum_count,
        "sum_unique_msgs": sum_unique,
        "n_hacked": n_hacked,
        "n_primary": n_primary,
        "top_domains": [{"domain": r["domain"], "count": r["count"]} for r in top_domains],
        "top_primary": [{"domain": r["domain"], "count": r["count"]} for r in top_primary],
    })


@app.route("/api/leaks/blackbasta-websites/messages")
def api_blackbasta_websites_messages():
    """Return the chat messages referenced by a given domain row."""
    domain = (request.args.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    try:
        page = max(1, int(request.args.get("page", 1)))
        size = min(200, max(1, int(request.args.get("size", 25))))
    except (TypeError, ValueError):
        page, size = 1, 25
    msg_q = (request.args.get("msg_q") or "").strip().lower()

    row = next((r for r in _load_blackbasta_websites() if r["domain"] == domain), None)
    if row is None:
        return jsonify({"error": "domain not found"}), 404

    index = _get_blackbasta_chat_index()
    keys = [k for k in (row.get("_msg_ids_raw") or "").split("|") if k]

    seen = set()
    msgs = []
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        rec = index.get(k)
        if rec is None:
            chat_id, _, ts = k.partition("@")
            msgs.append({
                "key": k, "chat_id": chat_id, "timestamp": ts,
                "sender_alias": "(unknown)",
                "message": "(message not found in chats dump)",
            })
        else:
            msgs.append({
                "key": k,
                "chat_id": rec.get("chat_id", ""),
                "timestamp": rec.get("timestamp", ""),
                "sender_alias": rec.get("sender_alias", ""),
                "message": rec.get("message", ""),
            })

    if msg_q:
        msgs = [m for m in msgs if msg_q in (m.get("message") or "").lower()]

    msgs.sort(key=lambda m: m.get("timestamp", ""))
    total = len(msgs)
    start = (page - 1) * size
    page_data = msgs[start:start + size]
    last_page = max(1, math.ceil(total / size)) if total else 1

    return jsonify({
        "domain": domain,
        "total": total,
        "last_page": last_page,
        "data": page_data,
    })


# ── Conti leaks (Jabber + Rocket Chat, server-side pagination) ──

_conti_cache = {}

CONTI_SOURCES = {
    "jabber_2020": {
        "label": "Jabber Chat (2020)",
        "path": os.path.join("leaks", "conti", "jabber_chat_2020_translated.csv"),
        "kind": "jabber",
    },
    "jabber_2021_2022": {
        "label": "Jabber Chat (2021–2022)",
        "path": os.path.join("leaks", "conti", "jabber_chat_2021_2022_translated.csv"),
        "kind": "jabber",
    },
    "rocket_chat": {
        "label": "Rocket Chat",
        "path": os.path.join("leaks", "conti", "rocket_chat_translated.csv"),
        "kind": "rocket",
    },
}


def _load_conti(source):
    """Load and normalize a Conti leak source into a list of dicts with
    a uniform schema: ts, from, to, body, body_en, body_language, channel.
    """
    if source not in CONTI_SOURCES:
        return []
    if source in _conti_cache:
        return _conti_cache[source]

    cfg = CONTI_SOURCES[source]
    path = os.path.join(DATA_DIR, cfg["path"])
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if cfg["kind"] == "jabber":
            for r in reader:
                rows.append({
                    "ts": (r.get("ts") or "").strip(),
                    "from": (r.get("from") or "").strip(),
                    "to": (r.get("to") or "").strip(),
                    "channel": "",
                    "body": r.get("body") or "",
                    "body_en": r.get("body_en") or "",
                    "body_language": (r.get("body_language") or "").strip(),
                })
        else:  # rocket
            for r in reader:
                rows.append({
                    "ts": (r.get("ts") or "").strip(),
                    "from": (r.get("from") or r.get("u.username") or "").strip(),
                    "to": (r.get("to") or r.get("rid") or "").strip(),
                    "channel": (r.get("rid") or "").strip(),
                    "body": r.get("msg-ru") or "",
                    "body_en": r.get("msg_en") or "",
                    "body_language": (r.get("msg_language") or "").strip(),
                })

    _conti_cache[source] = rows
    return rows


def _filter_conti(rows):
    args = request.args
    q = (args.get("filter_q") or "").strip().lower()
    sender = (args.get("filter_from") or "").strip().lower()
    recipient = (args.get("filter_to") or "").strip().lower()
    body = (args.get("filter_body") or "").strip().lower()
    lang = (args.get("filter_language") or "").strip().lower()
    date_from = (args.get("filter_date_from") or "").strip()
    date_to = (args.get("filter_date_to") or "").strip()

    out = rows
    if q:
        out = [r for r in out if
               q in r["body"].lower()
               or q in r["body_en"].lower()
               or q in r["from"].lower()
               or q in r["to"].lower()]
    if sender:
        out = [r for r in out if sender in r["from"].lower()]
    if recipient:
        out = [r for r in out if recipient in r["to"].lower()]
    if body:
        out = [r for r in out
               if body in r["body"].lower() or body in r["body_en"].lower()]
    if lang:
        out = [r for r in out if r["body_language"].lower() == lang]
    if date_from:
        out = [r for r in out if r["ts"] >= date_from]
    if date_to:
        out = [r for r in out if r["ts"] <= date_to]
    return out


@app.route("/leaks/conti")
def conti_leaks():
    return render_template(
        "conti_leaks.html",
        sources=[{"key": k, "label": v["label"]} for k, v in CONTI_SOURCES.items()],
    )


@app.route("/api/leaks/conti")
def api_conti_leaks():
    source = request.args.get("source", "jabber_2020")
    if source not in CONTI_SOURCES:
        return jsonify({"error": "unknown source"}), 400

    data = _load_conti(source)
    filtered = _filter_conti(data)

    sort_field = request.args.get("sort_field", "ts")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_field in ("ts", "from", "to", "body", "body_en", "body_language", "channel"):
        filtered = sorted(
            filtered,
            key=lambda r: (r.get(sort_field) or "").lower()
                          if isinstance(r.get(sort_field), str) else (r.get(sort_field) or ""),
            reverse=(sort_dir == "desc"),
        )

    total = len(filtered)
    page = max(1, int(request.args.get("page", 1)))
    size = min(200, max(1, int(request.args.get("size", 50))))
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "total": total,
        "data": page_data,
    })


@app.route("/api/leaks/conti/stats")
def api_conti_leaks_stats():
    source = request.args.get("source", "jabber_2020")
    if source not in CONTI_SOURCES:
        return jsonify({"error": "unknown source"}), 400

    data = _load_conti(source)
    filtered = _filter_conti(data)

    senders = set()
    recipients = set()
    langs = defaultdict(int)
    sender_counts = defaultdict(int)
    recipient_counts = defaultdict(int)
    min_ts = None
    max_ts = None
    for r in filtered:
        senders.add(r["from"])
        recipients.add(r["to"])
        if r["body_language"]:
            langs[r["body_language"]] += 1
        sender_counts[r["from"]] += 1
        recipient_counts[r["to"]] += 1
        ts = r["ts"]
        if ts:
            if min_ts is None or ts < min_ts:
                min_ts = ts
            if max_ts is None or ts > max_ts:
                max_ts = ts

    top_senders = sorted(sender_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
    top_recipients = sorted(recipient_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
    lang_breakdown = sorted(langs.items(), key=lambda kv: kv[1], reverse=True)

    return jsonify({
        "source": source,
        "source_label": CONTI_SOURCES[source]["label"],
        "total_messages": len(filtered),
        "distinct_senders": len(senders),
        "distinct_recipients": len(recipients),
        "earliest": min_ts or "",
        "latest": max_ts or "",
        "languages": [{"language": k, "count": v} for k, v in lang_breakdown],
        "top_senders": [{"from": s, "count": c} for s, c in top_senders],
        "top_recipients": [{"to": s, "count": c} for s, c in top_recipients],
    })


# ── CISA KEV (Known Exploited Vulnerabilities, live from cisa.gov) ──

import time as _time
from datetime import datetime as _datetime

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

_kev_cache = {
    "rows": None,
    "fetched_at": None,   # epoch seconds
    "source_url": CISA_KEV_URL,
    "error": None,
}


def _fetch_kev(force=False):
    """Fetch CISA KEV CSV into memory. Caches indefinitely until force=True."""
    if (not force) and _kev_cache["rows"] is not None:
        return _kev_cache["rows"]
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30,
                            headers={"User-Agent": "ransomware-analytics/1.0"})
        resp.raise_for_status()
        text = resp.content.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        rows = []
        for r in reader:
            # Normalize keys (strip whitespace) and keep original values as strings
            rows.append({(k or "").strip(): (v or "").strip() for k, v in r.items()})
        _kev_cache["rows"] = rows
        _kev_cache["fetched_at"] = _time.time()
        _kev_cache["error"] = None
    except Exception as exc:
        _kev_cache["error"] = str(exc)
        if _kev_cache["rows"] is None:
            _kev_cache["rows"] = []
        raise
    return _kev_cache["rows"]


def _filter_kev(rows):
    args = request.args
    q = (args.get("filter_q") or "").strip().lower()
    vendor = (args.get("filter_vendorProject") or "").strip().lower()
    product = (args.get("filter_product") or "").strip().lower()
    cve = (args.get("filter_cveID") or "").strip().lower()
    name = (args.get("filter_vulnerabilityName") or "").strip().lower()
    ransomware = (args.get("filter_knownRansomwareCampaignUse") or "").strip().lower()
    cwe = (args.get("filter_cwes") or "").strip().lower()
    date_from = (args.get("filter_date_from") or "").strip()  # YYYY-MM-DD
    date_to = (args.get("filter_date_to") or "").strip()

    out = rows
    if q:
        out = [r for r in out if any(
            q in (r.get(f, "") or "").lower()
            for f in ("cveID", "vendorProject", "product", "vulnerabilityName",
                      "shortDescription", "requiredAction", "notes", "cwes")
        )]
    if vendor:
        out = [r for r in out if vendor in (r.get("vendorProject", "") or "").lower()]
    if product:
        out = [r for r in out if product in (r.get("product", "") or "").lower()]
    if cve:
        out = [r for r in out if cve in (r.get("cveID", "") or "").lower()]
    if name:
        out = [r for r in out if name in (r.get("vulnerabilityName", "") or "").lower()]
    if cwe:
        out = [r for r in out if cwe in (r.get("cwes", "") or "").lower()]
    if ransomware:
        # values: "Known", "Unknown"
        out = [r for r in out
               if (r.get("knownRansomwareCampaignUse", "") or "").lower() == ransomware]
    if date_from:
        out = [r for r in out if (r.get("dateAdded", "") or "") >= date_from]
    if date_to:
        out = [r for r in out if (r.get("dateAdded", "") or "") <= date_to]
    return out


@app.route("/kev")
def kev_page():
    return render_template("kev.html")


@app.route("/api/kev")
def api_kev():
    force = request.args.get("refresh", "").lower() in ("1", "true", "yes")
    try:
        data = _fetch_kev(force=force)
    except Exception as exc:
        return jsonify({"error": f"Failed to fetch KEV: {exc}"}), 502

    filtered = _filter_kev(data)

    sort_field = request.args.get("sort_field", "dateAdded")
    sort_dir = request.args.get("sort_dir", "desc")
    if sort_field:
        reverse = sort_dir == "desc"
        filtered = sorted(
            filtered,
            key=lambda r: (r.get(sort_field) or "").lower()
                          if isinstance(r.get(sort_field), str) else (r.get(sort_field) or ""),
            reverse=reverse,
        )

    total = len(filtered)
    page = max(1, int(request.args.get("page", 1)))
    size = min(500, max(1, int(request.args.get("size", 50))))
    start = (page - 1) * size
    page_data = filtered[start:start + size]
    last_page = max(1, math.ceil(total / size))

    return jsonify({
        "last_page": last_page,
        "total": total,
        "data": page_data,
        "fetched_at": _kev_cache["fetched_at"],
        "source_url": _kev_cache["source_url"],
    })


@app.route("/api/kev/stats")
def api_kev_stats():
    try:
        data = _fetch_kev(force=False)
    except Exception as exc:
        return jsonify({"error": f"Failed to fetch KEV: {exc}"}), 502

    filtered = _filter_kev(data)

    vendors = defaultdict(int)
    products = defaultdict(int)
    ransomware_known = 0
    min_date = None
    max_date = None
    for r in filtered:
        v = r.get("vendorProject", "") or ""
        p = r.get("product", "") or ""
        if v:
            vendors[v] += 1
        if v or p:
            products[(v, p)] += 1
        if (r.get("knownRansomwareCampaignUse", "") or "").lower() == "known":
            ransomware_known += 1
        d = r.get("dateAdded", "") or ""
        if d:
            if min_date is None or d < min_date:
                min_date = d
            if max_date is None or d > max_date:
                max_date = d

    top_vendors = sorted(vendors.items(), key=lambda kv: kv[1], reverse=True)[:15]
    top_products = sorted(products.items(), key=lambda kv: kv[1], reverse=True)[:15]

    fetched_at = _kev_cache["fetched_at"]
    fetched_iso = (
        _datetime.utcfromtimestamp(fetched_at).strftime("%Y-%m-%d %H:%M:%S UTC")
        if fetched_at else None
    )

    return jsonify({
        "total": len(filtered),
        "ransomware_known": ransomware_known,
        "earliest_added": min_date or "",
        "latest_added": max_date or "",
        "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
        "top_products": [{"vendor": v, "product": p, "count": c}
                         for (v, p), c in top_products],
        "fetched_at": fetched_at,
        "fetched_at_iso": fetched_iso,
        "source_url": _kev_cache["source_url"],
    })


 # ── Logistic Regression (interactive) ──────────────────────────


def _coerce_value(val):
    """Try numeric conversion, otherwise keep as cleaned string."""
    if val is None:
        return None
    if isinstance(val, (int, float, np.integer, np.floating)):
        return float(val)
    text = str(val).strip()
    if text == "":
        return None
    try:
        return float(text)
    except ValueError:
        return text


def _build_feature_meta(clean_rows, feature_names):
    meta = {}
    for feat in feature_names:
        vals = [r[feat] for r in clean_rows]
        numeric_vals = [v for v in vals if isinstance(v, (int, float, np.integer, np.floating))]
        if len(numeric_vals) == len(vals):
            uniq = sorted(set(float(v) for v in numeric_vals))
            if uniq == [0.0, 1.0]:
                meta[feat] = {
                    "type": "binary",
                    "options": [0, 1],
                    "default": 0,
                }
            else:
                mn = float(min(numeric_vals))
                mx = float(max(numeric_vals))
                med = float(np.median(numeric_vals))
                meta[feat] = {
                    "type": "numeric",
                    "min": round(mn, 4),
                    "max": round(mx, 4),
                    "default": round(med, 4),
                    "integer": all(float(v).is_integer() for v in numeric_vals),
                }
        else:
            cats = sorted(set(str(v) for v in vals))
            meta[feat] = {
                "type": "categorical",
                "options": cats,
                "default": cats[0] if cats else "",
            }
    return meta


def _fit_logistic_from_clean_rows(clean_rows, y, feature_names, target_name, curve_feature=None):
    """Fit logistic regression with numeric and categorical predictors via DictVectorizer."""
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import confusion_matrix

    n = len(clean_rows)
    if n < 10:
        raise ValueError("Need at least 10 usable rows")

    # Train/test split (70/30)
    rng = np.random.default_rng(123)
    idx = np.arange(n)
    rng.shuffle(idx)
    split = int(0.7 * n)
    train_idx = idx[:split]
    test_idx = idx[split:]

    X_train_rows = [clean_rows[i] for i in train_idx]
    y_train = y[train_idx]
    X_test_rows = [clean_rows[i] for i in test_idx]
    y_test = y[test_idx]

    vec = DictVectorizer(sparse=False)
    X_train = vec.fit_transform(X_train_rows)
    X_test = vec.transform(X_test_rows)
    X_all = vec.transform(clean_rows)

    model = LogisticRegression(max_iter=2000, solver="lbfgs")
    model.fit(X_train, y_train)

    # Metrics on test set
    y_test_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_test_pred, labels=[0, 1])
    accuracy = float(np.trace(cm) / cm.sum()) if cm.sum() else 0.0

    # Predictions on all rows for table
    y_all_prob = model.predict_proba(X_all)[:, 1]
    y_all_pred = model.predict(X_all)

    feature_meta = _build_feature_meta(clean_rows, feature_names)

    # Coefficients are in expanded encoded space
    expanded = vec.get_feature_names_out()
    coefs = model.coef_[0]
    coefficient_rows = [{
        "feature": "intercept",
        "coefficient": round(float(model.intercept_[0]), 4),
        "odds_ratio": None,
    }]
    for i, feat in enumerate(expanded):
        coefficient_rows.append({
            "feature": feat,
            "coefficient": round(float(coefs[i]), 4),
            "odds_ratio": round(float(np.exp(coefs[i])), 4),
        })

    # Curve uses a numeric feature only
    numeric_features = [f for f in feature_names if feature_meta[f]["type"] == "numeric"]
    if curve_feature in numeric_features:
        curve_feat = curve_feature
    elif numeric_features:
        curve_feat = numeric_features[0]
    else:
        curve_feat = None

    curve_x, curve_y, scatter_x = [], [], []
    if curve_feat is not None:
        from sklearn.linear_model import LogisticRegression as LR1

        x_vals = np.array([float(r[curve_feat]) for r in clean_rows])
        simple_model = LR1(max_iter=2000, solver="lbfgs")
        simple_model.fit(x_vals.reshape(-1, 1), y)
        x_min, x_max = float(np.min(x_vals)), float(np.max(x_vals))
        margin = max((x_max - x_min) * 0.1, 1)
        x_seq = np.linspace(x_min - margin, x_max + margin, 200)
        p_seq = simple_model.predict_proba(x_seq.reshape(-1, 1))[:, 1]
        curve_x = [round(float(v), 4) for v in x_seq]
        curve_y = [round(float(v), 4) for v in p_seq]
        scatter_x = [round(float(v), 4) for v in x_vals]
    else:
        scatter_x = [float(i) for i in range(n)]

    # Data table rows
    table_rows = []
    for i, row in enumerate(clean_rows):
        out = {}
        for f in feature_names:
            v = row[f]
            if isinstance(v, (int, float, np.integer, np.floating)):
                fv = float(v)
                out[f] = int(fv) if fv.is_integer() else round(fv, 4)
            else:
                out[f] = str(v)
        out[target_name] = int(y[i])
        out["predicted_prob"] = round(float(y_all_prob[i]), 4)
        out["predicted_class"] = int(y_all_pred[i])
        table_rows.append(out)

    return {
        "feature_names": feature_names,
        "target_name": target_name,
        "feature_meta": feature_meta,
        "coefficient_rows": coefficient_rows,
        "confusion_matrix": {
            "tn": int(cm[0][0]),
            "fp": int(cm[0][1]),
            "fn": int(cm[1][0]),
            "tp": int(cm[1][1]),
        },
        "accuracy": round(accuracy, 4),
        "error_rate": round(1 - accuracy, 4),
        "n": n,
        "n_positive": int(np.sum(y)),
        "curve_feature": curve_feat,
        "curve": {"x": curve_x, "y": curve_y},
        "scatter": {
            "x": scatter_x,
            "y": [int(v) for v in y],
        },
        "data": table_rows,
    }


def _prepare_uploaded_rows(rows, predictor_cols, target_col):
    clean_rows = []
    y_vals = []
    skipped = 0

    for row in rows:
        target_raw = _coerce_value(row.get(target_col))
        if target_raw is None:
            skipped += 1
            continue
        try:
            target_num = float(target_raw)
        except (TypeError, ValueError):
            skipped += 1
            continue
        if target_num not in (0.0, 1.0):
            skipped += 1
            continue

        feat_row = {}
        valid = True
        for col in predictor_cols:
            val = _coerce_value(row.get(col))
            if val is None:
                valid = False
                break
            feat_row[col] = val
        if not valid:
            skipped += 1
            continue

        clean_rows.append(feat_row)
        y_vals.append(int(target_num))

    return clean_rows, np.array(y_vals, dtype=int), skipped


def _generate_lgr_demo_rows(seed=42, n=500):
    """Replicate lgr.r v2 with numeric + binary + categorical predictors."""
    rng = np.random.default_rng(seed)

    vulnerabilities = rng.poisson(lam=5, size=n)
    days_no_update = np.round(rng.uniform(1, 365, size=n)).astype(int)
    monthly_visitors = np.round(rng.lognormal(mean=3, sigma=1, size=n)).astype(int)
    has_waf = rng.binomial(1, 0.4, size=n)

    sectors = np.array(["finance", "healthcare", "retail", "government"])
    sector = rng.choice(sectors, size=n, p=[0.25, 0.25, 0.35, 0.15])

    sector_effect = np.where(
        sector == "finance", 0.5,
        np.where(sector == "healthcare", 0.8,
                 np.where(sector == "government", 1.2, 0.0))
    )

    linear_part = (
        -3
        + 0.4 * vulnerabilities
        + 0.008 * days_no_update
        + 0.01 * monthly_visitors
        - 1.5 * has_waf
        + sector_effect
    )
    prob_hacked = 1 / (1 + np.exp(-linear_part))
    hacked = rng.binomial(1, prob_hacked)

    rows = []
    for i in range(n):
        rows.append({
            "vulnerabilities": int(vulnerabilities[i]),
            "days_no_update": int(days_no_update[i]),
            "monthly_visitors": int(monthly_visitors[i]),
            "has_waf": int(has_waf[i]),
            "sector": str(sector[i]),
        })

    return rows, hacked


def _fit_demo_lgr():
    demo_rows, y = _generate_lgr_demo_rows()
    features = ["vulnerabilities", "days_no_update", "monthly_visitors", "has_waf", "sector"]
    return _fit_logistic_from_clean_rows(demo_rows, y, features, target_name="hacked", curve_feature="vulnerabilities")


_lgr_cache = None


def _get_lgr():
    global _lgr_cache
    if _lgr_cache is None:
        _lgr_cache = _fit_demo_lgr()
    return _lgr_cache


@app.route("/logistic-regression")
def logistic_regression():
    return render_template("logistic_regression.html")


@app.route("/api/logistic-regression")
def api_logistic_regression():
    return jsonify(_get_lgr())


@app.route("/api/logistic-regression/predict")
def api_lgr_predict():
    """Predict P(hacked=1) for user-supplied inputs using the demo model."""
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression

    rows, y = _generate_lgr_demo_rows()
    features = ["vulnerabilities", "days_no_update", "monthly_visitors", "has_waf", "sector"]

    vec = DictVectorizer(sparse=False)
    X = vec.fit_transform(rows)
    model = LogisticRegression(max_iter=2000, solver="lbfgs")
    model.fit(X, y)

    input_row = {
        "vulnerabilities": _coerce_value(request.args.get("vulnerabilities", 5)) or 5,
        "days_no_update": _coerce_value(request.args.get("days_no_update", 180)) or 180,
        "monthly_visitors": _coerce_value(request.args.get("monthly_visitors", 50)) or 50,
        "has_waf": _coerce_value(request.args.get("has_waf", 0)) or 0,
        "sector": str(request.args.get("sector", "retail")).strip() or "retail",
    }

    x_new = vec.transform([input_row])
    prob = model.predict_proba(x_new)[0, 1]
    return jsonify({"probability": round(float(prob), 4)})


# ── User-uploaded data for logistic regression ──

_user_lgr_store = {}   # session-id -> {"raw": [...], "columns": [...]}


@app.route("/api/logistic-regression/upload", methods=["POST"])
def api_lgr_upload():
    """Accept a CSV upload; return columns + first 5 rows for preview."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    fname = secure_filename(f.filename)
    if not fname.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are supported"}), 400

    try:
        text = f.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
    except Exception as e:
        return jsonify({"error": f"Failed to parse CSV: {e}"}), 400

    if len(rows) < 10:
        return jsonify({"error": "Dataset too small (need at least 10 rows)"}), 400

    columns = list(rows[0].keys())

    # Store in server-side dict keyed by a session id
    import uuid
    sid = str(uuid.uuid4())

    _user_lgr_store[sid] = {"rows": rows, "columns": columns}

    return jsonify({
        "session_id": sid,
        "columns": columns,
        "n_rows": len(rows),
        "preview": rows[:5],
    })


@app.route("/api/logistic-regression/fit", methods=["POST"])
def api_lgr_fit():
    """Fit logistic regression on user-uploaded data with chosen columns."""
    from sklearn.linear_model import LogisticRegression

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    sid = body.get("session_id", "")
    target_col = body.get("target", "")
    predictor_cols = body.get("predictors", [])
    curve_col = body.get("curve_feature", "")

    if sid not in _user_lgr_store:
        return jsonify({"error": "Session expired or invalid. Please re-upload."}), 400
    if not target_col or not predictor_cols:
        return jsonify({"error": "Select a target and at least one predictor."}), 400

    store = _user_lgr_store[sid]
    rows = store["rows"]
    all_cols = store["columns"]

    # Validate columns exist
    for c in [target_col] + predictor_cols:
        if c not in all_cols:
            return jsonify({"error": f"Column '{c}' not found in data."}), 400

    clean_rows, y, skipped = _prepare_uploaded_rows(rows, predictor_cols, target_col)
    if len(y) < 10:
        return jsonify({
            "error": f"Only {len(y)} usable rows found (need at least 10). Target must be binary 0/1 and predictors non-empty."
        }), 400

    try:
        result = _fit_logistic_from_clean_rows(
            clean_rows,
            y,
            predictor_cols,
            target_name=target_col,
            curve_feature=curve_col,
        )
    except Exception as e:
        return jsonify({"error": f"Model fitting failed: {e}"}), 400

    result["skipped_rows"] = skipped
    return jsonify(result)


@app.route("/api/logistic-regression/predict-custom", methods=["POST"])
def api_lgr_predict_custom():
    """Predict P(target=1) for user inputs using a freshly-fit model on uploaded data."""
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    sid = body.get("session_id", "")
    target_col = body.get("target", "")
    predictor_cols = body.get("predictors", [])
    values = body.get("values", {})

    if sid not in _user_lgr_store:
        return jsonify({"error": "Session expired. Please re-upload."}), 400

    store = _user_lgr_store[sid]
    rows = store["rows"]

    clean_rows, y, _ = _prepare_uploaded_rows(rows, predictor_cols, target_col)
    if len(y) < 10:
        return jsonify({"error": "Not enough usable rows to fit model."}), 400

    vec = DictVectorizer(sparse=False)
    X = vec.fit_transform(clean_rows)

    model = LogisticRegression(max_iter=2000, solver="lbfgs")
    model.fit(X, y)

    input_row = {}
    for c in predictor_cols:
        v = _coerce_value(values.get(c))
        if v is None:
            return jsonify({"error": f"Missing value for predictor '{c}'"}), 400
        input_row[c] = v

    x_new = vec.transform([input_row])
    prob = model.predict_proba(x_new)[0, 1]

    return jsonify({"probability": round(float(prob), 4)})


# ── Odds Ratio (interactive) ──────────────────────────────────
#
# Notation per project convention (webapp_rules.instructions.md):
#   (a) = Ransomed using Tech       (exposed + outcome)
#   (b) = Ransomed not using Tech   (unexposed + outcome)
#   (c) = NoRansomed using Tech     (exposed + no outcome)
#   (d) = NoRansomed not using Tech (unexposed + no outcome)


def _compute_odds_ratio(a, b, c, d):
    """Return OR + 95% CI + p-value (Wald) for a 2x2 table.

    Applies Haldane-Anscombe correction (+0.5 to all cells) when any cell is 0.
    """
    a = float(a); b = float(b); c = float(c); d = float(d)
    n = a + b + c + d
    if n <= 0:
        return {"error": "All cells are zero."}

    zero_cell = (a == 0) or (b == 0) or (c == 0) or (d == 0)
    aa, bb, cc, dd = (a + 0.5, b + 0.5, c + 0.5, d + 0.5) if zero_cell else (a, b, c, d)

    if bb * cc == 0:
        return {"error": "Cannot compute OR (denominator is 0)."}

    or_val = (aa * dd) / (bb * cc)
    log_or = math.log(or_val)
    se = math.sqrt(1.0 / aa + 1.0 / bb + 1.0 / cc + 1.0 / dd)
    z = log_or / se if se > 0 else 0.0

    # Two-sided p-value from standard normal: p = 2 * (1 - Phi(|z|))
    # Use math.erf for normal CDF
    p_value = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2))))
    ci_lo = math.exp(log_or - 1.96 * se)
    ci_hi = math.exp(log_or + 1.96 * se)

    # Risk metrics (interpretive)
    risk_exposed = a / (a + c) if (a + c) > 0 else None
    risk_unexposed = b / (b + d) if (b + d) > 0 else None
    rr = (risk_exposed / risk_unexposed) if risk_unexposed not in (None, 0) and risk_exposed is not None else None
    arr = (risk_exposed - risk_unexposed) if (risk_exposed is not None and risk_unexposed is not None) else None

    return {
        "a": int(a), "b": int(b), "c": int(c), "d": int(d),
        "n": int(n),
        "zero_cell_correction": zero_cell,
        "odds_ratio": round(or_val, 4),
        "log_or": round(log_or, 4),
        "se_log_or": round(se, 4),
        "ci_lo": round(ci_lo, 4),
        "ci_hi": round(ci_hi, 4),
        "z": round(z, 4),
        "p_value": round(p_value, 6),
        "risk_exposed": round(risk_exposed, 4) if risk_exposed is not None else None,
        "risk_unexposed": round(risk_unexposed, 4) if risk_unexposed is not None else None,
        "relative_risk": round(rr, 4) if rr is not None else None,
        "abs_risk_diff": round(arr, 4) if arr is not None else None,
    }


@app.route("/odds-ratio")
def odds_ratio_page():
    return render_template("odds_ratio.html")


@app.route("/api/odds-ratio/compute", methods=["POST"])
def api_or_compute():
    """Compute OR from manual a,b,c,d input."""
    body = request.get_json(silent=True) or {}
    try:
        a = float(body.get("a", 0))
        b = float(body.get("b", 0))
        c = float(body.get("c", 0))
        d = float(body.get("d", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "All cells must be numeric."}), 400

    if min(a, b, c, d) < 0:
        return jsonify({"error": "Cells cannot be negative."}), 400

    return jsonify(_compute_odds_ratio(a, b, c, d))


@app.route("/api/odds-ratio/from-csv", methods=["POST"])
def api_or_from_csv():
    """Compute OR from an uploaded dataset by selecting exposure and outcome columns.

    Body JSON:
      session_id   : id from /api/logistic-regression/upload (reused store)
      exposure     : column name for exposure (Tech) — 0/1 or values
      outcome      : column name for outcome (Ransomed) — 0/1 or values
      exposure_pos : optional value treated as "exposed" (default: 1 / "1" / "yes" / "true")
      outcome_pos  : optional value treated as "outcome positive" (default: 1)
    """
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id", "")
    exposure_col = body.get("exposure", "")
    outcome_col = body.get("outcome", "")
    exposure_pos = body.get("exposure_pos")
    outcome_pos = body.get("outcome_pos")

    if sid not in _user_lgr_store:
        return jsonify({"error": "Session expired or invalid. Please re-upload."}), 400
    if not exposure_col or not outcome_col:
        return jsonify({"error": "Pick exposure and outcome columns."}), 400
    if exposure_col == outcome_col:
        return jsonify({"error": "Exposure and outcome must be different columns."}), 400

    store = _user_lgr_store[sid]
    rows = store["rows"]
    cols = store["columns"]
    if exposure_col not in cols or outcome_col not in cols:
        return jsonify({"error": "Selected column not found in dataset."}), 400

    def _is_positive(value, positive_marker):
        if value is None:
            return None
        text = str(value).strip().lower()
        if text == "":
            return None
        if positive_marker is not None:
            return text == str(positive_marker).strip().lower()
        # auto-detect common truthy markers
        if text in {"1", "1.0", "true", "yes", "y", "t"}:
            return True
        if text in {"0", "0.0", "false", "no", "n", "f"}:
            return False
        return None

    a = b = c = d = 0
    skipped = 0
    for r in rows:
        ex = _is_positive(r.get(exposure_col), exposure_pos)
        ou = _is_positive(r.get(outcome_col), outcome_pos)
        if ex is None or ou is None:
            skipped += 1
            continue
        if ex and ou:
            a += 1
        elif (not ex) and ou:
            b += 1
        elif ex and (not ou):
            c += 1
        else:
            d += 1

    if (a + b + c + d) == 0:
        return jsonify({"error": "No usable rows. Check that columns are binary or set positive values."}), 400

    result = _compute_odds_ratio(a, b, c, d)
    result["skipped_rows"] = skipped
    result["exposure"] = exposure_col
    result["outcome"] = outcome_col
    return jsonify(result)


@app.route("/api/odds-ratio/column-values", methods=["POST"])
def api_or_column_values():
    """Return the unique values found in a column of the uploaded CSV.

    Helps the UI suggest 'positive value' choices and detect categorical columns.
    """
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id", "")
    col = body.get("column", "")
    if sid not in _user_lgr_store:
        return jsonify({"error": "Session expired."}), 400
    store = _user_lgr_store[sid]
    if col not in store["columns"]:
        return jsonify({"error": "Column not found."}), 400

    counts = {}
    for r in store["rows"]:
        v = r.get(col)
        if v is None:
            continue
        text = str(v).strip()
        if text == "":
            continue
        counts[text] = counts.get(text, 0) + 1

    items = sorted(counts.items(), key=lambda kv: -kv[1])
    return jsonify({
        "column": col,
        "n_unique": len(items),
        "values": [{"value": k, "count": v} for k, v in items[:50]],
    })


@app.route("/api/odds-ratio/by-category", methods=["POST"])
def api_or_by_category():
    """Compute OR per category of a multi-valued exposure column vs a binary outcome.

    Body:
      session_id     : upload session id
      exposure       : column with multiple categories (e.g. sector)
      outcome        : binary outcome column (e.g. hacked)
      outcome_pos    : value treated as outcome=1 (default: auto-detect 1/yes/true)
      baseline       : optional baseline category. If omitted -> compare each category vs ALL OTHERS.
    """
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id", "")
    exposure_col = body.get("exposure", "")
    outcome_col = body.get("outcome", "")
    outcome_pos = body.get("outcome_pos")
    baseline = body.get("baseline")

    if sid not in _user_lgr_store:
        return jsonify({"error": "Session expired or invalid."}), 400
    if not exposure_col or not outcome_col:
        return jsonify({"error": "Pick exposure (categorical) and outcome columns."}), 400
    if exposure_col == outcome_col:
        return jsonify({"error": "Exposure and outcome must differ."}), 400

    store = _user_lgr_store[sid]
    if exposure_col not in store["columns"] or outcome_col not in store["columns"]:
        return jsonify({"error": "Column not found."}), 400

    def _to_outcome(v):
        if v is None:
            return None
        t = str(v).strip().lower()
        if t == "":
            return None
        if outcome_pos is not None:
            return t == str(outcome_pos).strip().lower()
        if t in {"1", "1.0", "true", "yes", "y", "t"}:
            return True
        if t in {"0", "0.0", "false", "no", "n", "f"}:
            return False
        return None

    # Build per-category contingency: cat -> (outcome=1, outcome=0)
    table = {}
    skipped = 0
    for r in store["rows"]:
        cat = r.get(exposure_col)
        ou = _to_outcome(r.get(outcome_col))
        if cat is None or str(cat).strip() == "" or ou is None:
            skipped += 1
            continue
        cat = str(cat).strip()
        slot = table.setdefault(cat, [0, 0])
        slot[0 if ou else 1] += 1

    if not table:
        return jsonify({"error": "No usable rows. Check the outcome column or set 'positive value'."}), 400

    categories = sorted(table.keys())
    if baseline is not None and baseline != "" and baseline not in table:
        return jsonify({"error": f"Baseline '{baseline}' not found among categories."}), 400

    rows_out = []
    for cat in categories:
        a = table[cat][0]    # exposed (in this cat) & outcome=1
        c = table[cat][1]    # exposed (in this cat) & outcome=0
        if baseline:
            if cat == baseline:
                rows_out.append({
                    "category": cat,
                    "is_baseline": True,
                    "n_exposed": a + c,
                    "n_outcome_in_exposed": a,
                    "risk": round(a / (a + c), 4) if (a + c) > 0 else None,
                    "odds_ratio": 1.0,
                    "ci_lo": None, "ci_hi": None, "p_value": None,
                })
                continue
            b = table[baseline][0]
            d = table[baseline][1]
        else:
            # vs all others
            b = sum(v[0] for k, v in table.items() if k != cat)
            d = sum(v[1] for k, v in table.items() if k != cat)

        stats = _compute_odds_ratio(a, b, c, d)
        rows_out.append({
            "category": cat,
            "is_baseline": False,
            "n_exposed": a + c,
            "n_outcome_in_exposed": a,
            "risk": round(a / (a + c), 4) if (a + c) > 0 else None,
            "odds_ratio": stats.get("odds_ratio"),
            "ci_lo": stats.get("ci_lo"),
            "ci_hi": stats.get("ci_hi"),
            "p_value": stats.get("p_value"),
            "zero_cell_correction": stats.get("zero_cell_correction"),
            "a": stats.get("a"), "b": stats.get("b"),
            "c": stats.get("c"), "d": stats.get("d"),
        })

    return jsonify({
        "exposure": exposure_col,
        "outcome": outcome_col,
        "baseline": baseline or None,
        "comparison": "vs baseline" if baseline else "vs all other categories",
        "skipped_rows": skipped,
        "rows": rows_out,
        "categories": categories,
    })


# ── Factor Analysis (NMF / SVD) on tech co-occurrence ──────────
#
# Use case: given many sites and ~thousands of technologies, identify latent
# "tech stacks" (groups of technologies that tend to appear together).
# These low-dimensional components can then replace 10k dummy variables in
# logistic regression.

# Storage for uploaded factor analysis matrices, keyed by session_id
_user_fa_store = {}  # sid -> {"matrix": csr_matrix, "sites": [...], "techs": [...], "filename": str}


def _build_binary_matrix(rows, mode, site_col=None, tech_col=None,
                         tech_columns=None, min_tech_count=1, min_site_techs=1):
    """Build a binary site x tech sparse matrix from uploaded rows.

    mode = "long"   : rows have site_col + tech_col columns. One row per (site, tech) pair.
    mode = "wide"   : rows have site_col + tech_columns, where each tech column is 0/1.
    """
    from scipy.sparse import csr_matrix

    site_index = {}
    tech_index = {}
    triples = []   # (site_idx, tech_idx, value)

    if mode == "long":
        if not site_col or not tech_col:
            raise ValueError("Long mode requires site_col and tech_col.")
        for r in rows:
            site = r.get(site_col)
            tech = r.get(tech_col)
            if site is None or tech is None:
                continue
            site = str(site).strip()
            tech = str(tech).strip()
            if site == "" or tech == "":
                continue
            si = site_index.setdefault(site, len(site_index))
            ti = tech_index.setdefault(tech, len(tech_index))
            triples.append((si, ti, 1))

    elif mode == "wide":
        if not site_col or not tech_columns:
            raise ValueError("Wide mode requires site_col and tech_columns.")
        for r in rows:
            site = r.get(site_col)
            if site is None:
                continue
            site = str(site).strip()
            if site == "":
                continue
            si = site_index.setdefault(site, len(site_index))
            for tech in tech_columns:
                v = r.get(tech)
                if v is None:
                    continue
                # accept 1, "1", "true", "yes"
                if isinstance(v, (int, float)):
                    on = v != 0
                else:
                    s = str(v).strip().lower()
                    on = s in {"1", "1.0", "true", "yes", "y", "t"}
                if on:
                    ti = tech_index.setdefault(tech, len(tech_index))
                    triples.append((si, ti, 1))
    else:
        raise ValueError(f"Unknown mode: {mode}")

    if not triples:
        raise ValueError("No site-tech pairs found. Check column choices.")

    n_sites = len(site_index)
    n_techs = len(tech_index)
    rows_arr = np.array([t[0] for t in triples], dtype=np.int32)
    cols_arr = np.array([t[1] for t in triples], dtype=np.int32)
    data_arr = np.ones(len(triples), dtype=np.float32)

    M = csr_matrix((data_arr, (rows_arr, cols_arr)), shape=(n_sites, n_techs))
    # collapse duplicates (long format may have repeats) -> binarize
    M.data = np.ones_like(M.data)
    M.sum_duplicates()
    M.data = np.minimum(M.data, 1.0)

    sites = sorted(site_index.keys(), key=lambda s: site_index[s])
    techs = sorted(tech_index.keys(), key=lambda t: tech_index[t])

    # filter rare techs and sparse sites
    if min_tech_count > 1:
        col_counts = np.asarray(M.sum(axis=0)).ravel()
        keep_cols = np.where(col_counts >= min_tech_count)[0]
        M = M[:, keep_cols]
        techs = [techs[i] for i in keep_cols]

    if min_site_techs > 0:
        row_counts = np.asarray(M.sum(axis=1)).ravel()
        keep_rows = np.where(row_counts >= min_site_techs)[0]
        M = M[keep_rows, :]
        sites = [sites[i] for i in keep_rows]

    return M, sites, techs


@app.route("/factor-analysis")
def factor_analysis_page():
    return render_template("factor_analysis.html")


@app.route("/api/factor-analysis/upload", methods=["POST"])
def api_fa_upload():
    """Upload CSV. Returns columns + preview so user can choose format."""
    import uuid
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    if not f.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files supported"}), 400

    try:
        text = f.stream.read().decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        if not rows:
            return jsonify({"error": "CSV is empty"}), 400
        cols = reader.fieldnames or []
    except Exception as e:
        return jsonify({"error": f"Failed to parse CSV: {e}"}), 400

    sid = uuid.uuid4().hex
    _user_fa_store[sid] = {
        "rows": rows,
        "columns": cols,
        "filename": secure_filename(f.filename),
        "matrix": None, "sites": None, "techs": None,
    }

    return jsonify({
        "session_id": sid,
        "filename": _user_fa_store[sid]["filename"],
        "n_rows": len(rows),
        "columns": cols,
        "preview": rows[:5],
    })


@app.route("/api/factor-analysis/build", methods=["POST"])
def api_fa_build():
    """Build the binary site x tech matrix from uploaded data."""
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id", "")
    mode = body.get("mode", "long")
    site_col = body.get("site_col")
    tech_col = body.get("tech_col")
    tech_columns = body.get("tech_columns") or []
    min_tech_count = int(body.get("min_tech_count", 2))
    min_site_techs = int(body.get("min_site_techs", 1))

    if sid not in _user_fa_store:
        return jsonify({"error": "Session expired."}), 400

    rows = _user_fa_store[sid]["rows"]
    try:
        M, sites, techs = _build_binary_matrix(
            rows, mode=mode, site_col=site_col, tech_col=tech_col,
            tech_columns=tech_columns,
            min_tech_count=min_tech_count, min_site_techs=min_site_techs,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    if M.shape[0] < 2 or M.shape[1] < 2:
        return jsonify({"error": f"Matrix too small after filtering: {M.shape}. Lower min_tech_count or min_site_techs."}), 400

    _user_fa_store[sid]["matrix"] = M
    _user_fa_store[sid]["sites"] = sites
    _user_fa_store[sid]["techs"] = techs

    # Tech frequency stats
    col_counts = np.asarray(M.sum(axis=0)).ravel().astype(int)
    top_idx = np.argsort(col_counts)[::-1][:30]
    top_techs = [{"tech": techs[i], "count": int(col_counts[i])} for i in top_idx]

    row_counts = np.asarray(M.sum(axis=1)).ravel().astype(int)

    return jsonify({
        "n_sites": M.shape[0],
        "n_techs": M.shape[1],
        "n_pairs": int(M.nnz),
        "density": round(float(M.nnz) / float(M.shape[0] * M.shape[1]), 6),
        "techs_per_site_mean": round(float(row_counts.mean()), 2),
        "techs_per_site_median": int(np.median(row_counts)),
        "sites_per_tech_mean": round(float(col_counts.mean()), 2),
        "top_techs": top_techs,
    })


@app.route("/api/factor-analysis/run", methods=["POST"])
def api_fa_run():
    """Run NMF or TruncatedSVD on the previously built matrix."""
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id", "")
    method = body.get("method", "nmf").lower()
    k = int(body.get("k", 10))
    top_n = int(body.get("top_n", 10))

    if sid not in _user_fa_store or _user_fa_store[sid].get("matrix") is None:
        return jsonify({"error": "Build the matrix first."}), 400

    store = _user_fa_store[sid]
    M = store["matrix"]
    techs = store["techs"]
    sites = store["sites"]

    n_sites, n_techs = M.shape
    k = max(2, min(k, min(n_sites, n_techs) - 1))

    components = []      # list[{component, top_techs:[{tech,weight}], strength}]
    site_scores = None   # numpy array (n_sites, k)
    summary = {"method": method, "k": k}

    if method == "nmf":
        from sklearn.decomposition import NMF
        # NMF works on non-negative matrices (we have 0/1)
        model = NMF(n_components=k, init="nndsvda", random_state=42, max_iter=400)
        W = model.fit_transform(M.toarray())   # (sites, k)
        H = model.components_                  # (k, techs)
        site_scores = W
        summary["reconstruction_err"] = round(float(model.reconstruction_err_), 4)
        summary["n_iter"] = int(model.n_iter_)

        for ci in range(k):
            row = H[ci]
            order = np.argsort(row)[::-1][:top_n]
            top = [{"tech": techs[j], "weight": round(float(row[j]), 4)} for j in order]
            components.append({
                "component": ci + 1,
                "strength": round(float(row.sum()), 4),
                "top_techs": top,
            })

    elif method == "svd":
        from sklearn.decomposition import TruncatedSVD
        model = TruncatedSVD(n_components=k, random_state=42)
        W = model.fit_transform(M)             # (sites, k)
        H = model.components_                  # (k, techs)
        site_scores = W
        summary["explained_variance_ratio"] = [round(float(v), 4) for v in model.explained_variance_ratio_]
        summary["total_explained_variance"] = round(float(model.explained_variance_ratio_.sum()), 4)
        summary["singular_values"] = [round(float(v), 4) for v in model.singular_values_]

        for ci in range(k):
            row = H[ci]
            # for SVD, also show negative loadings (rank by abs)
            order = np.argsort(np.abs(row))[::-1][:top_n]
            top = [{"tech": techs[j], "weight": round(float(row[j]), 4)} for j in order]
            components.append({
                "component": ci + 1,
                "strength": round(float(np.abs(row).sum()), 4),
                "top_techs": top,
            })
    else:
        return jsonify({"error": f"Unknown method '{method}'"}), 400

    # store scores so user can download them
    store["scores"] = site_scores
    store["scores_method"] = method
    store["scores_k"] = k

    return jsonify({
        "summary": summary,
        "components": components,
        "n_sites": n_sites,
        "n_techs": n_techs,
    })


@app.route("/api/factor-analysis/cooccurrence", methods=["POST"])
def api_fa_cooccurrence():
    """Compute Jaccard co-occurrence among the top-N most frequent techs."""
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id", "")
    top_n = int(body.get("top_n", 20))

    if sid not in _user_fa_store or _user_fa_store[sid].get("matrix") is None:
        return jsonify({"error": "Build the matrix first."}), 400

    store = _user_fa_store[sid]
    M = store["matrix"]
    techs = store["techs"]

    col_counts = np.asarray(M.sum(axis=0)).ravel()
    top_idx = np.argsort(col_counts)[::-1][:top_n]
    sub = M[:, top_idx].toarray().astype(np.int8)   # (n_sites, top_n)
    sub_techs = [techs[i] for i in top_idx]

    inter = sub.T @ sub                  # (top_n, top_n) intersection counts
    counts = sub.sum(axis=0)             # (top_n,)
    union = counts[:, None] + counts[None, :] - inter
    with np.errstate(divide="ignore", invalid="ignore"):
        jaccard = np.where(union > 0, inter / union, 0.0)

    # build heatmap data
    cells = []
    for i in range(len(sub_techs)):
        for j in range(len(sub_techs)):
            cells.append({
                "x": sub_techs[j], "y": sub_techs[i],
                "jaccard": round(float(jaccard[i, j]), 3),
                "intersection": int(inter[i, j]),
            })

    # also produce a "top pairs" list (i<j, sorted by jaccard desc)
    pairs = []
    for i in range(len(sub_techs)):
        for j in range(i + 1, len(sub_techs)):
            pairs.append({
                "tech_a": sub_techs[i],
                "tech_b": sub_techs[j],
                "intersection": int(inter[i, j]),
                "count_a": int(counts[i]),
                "count_b": int(counts[j]),
                "jaccard": round(float(jaccard[i, j]), 4),
            })
    pairs.sort(key=lambda p: -p["jaccard"])

    return jsonify({
        "techs": sub_techs,
        "counts": [int(c) for c in counts],
        "cells": cells,
        "top_pairs": pairs[:50],
    })


@app.route("/api/factor-analysis/download-scores", methods=["GET"])
def api_fa_download_scores():
    """Download site x component scores CSV (for use in logistic regression)."""
    from flask import Response
    sid = request.args.get("session_id", "")
    if sid not in _user_fa_store or _user_fa_store[sid].get("scores") is None:
        return jsonify({"error": "No scores available. Run NMF/SVD first."}), 400

    store = _user_fa_store[sid]
    scores = store["scores"]
    sites = store["sites"]
    k = store["scores_k"]
    method = store["scores_method"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["site"] + [f"{method}_c{i+1}" for i in range(k)])
    for i, s in enumerate(sites):
        writer.writerow([s] + [f"{scores[i, j]:.6f}" for j in range(k)])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="site_scores_{method}_k{k}.csv"'},
    )


if __name__ == "__main__":
    app.run(debug=True, port=8880)
