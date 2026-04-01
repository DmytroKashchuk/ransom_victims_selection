import csv
import math
import os
from collections import defaultdict
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
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


def _load_cve_results():
    global _cve_results_cache
    if _cve_results_cache is None:
        _cve_results_cache = load_csv(os.path.join("tech_cve", "tech_cve_results.csv"))
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


def _load_cve_normalized_results():
    global _cve_normalized_results_cache
    if _cve_normalized_results_cache is None:
        _cve_normalized_results_cache = load_csv(
            os.path.join("tech_cve_normalized", "tech_cve_results.csv")
        )
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


if __name__ == "__main__":
    app.run(debug=True, port=8880)
