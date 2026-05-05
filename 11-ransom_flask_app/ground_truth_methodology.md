# How we matched SWDB Products with CPE products

We do: `swdb.product = cpe.product AND swdb.vendor = cpe.vendor`.

## Step 1 — Normalize SWDB names

Strip legal suffixes (Inc, LLC, Ltd, GmbH, Corp, PLC, AG, Foundation), the prefix "The", trailing parentheticals, punctuation. Lowercase. Replace spaces/dashes/dots with underscores.

| Input | Normalized |
|---|---|
| `The Apache Software Foundation` | `apache_software_foundation` |
| `Cisco Systems Inc.` | `cisco_systems` |
| `Adobe Systems Inc., (US) LLC.` | `adobe_systems` |

## Step 2 — Download CPE dictionary

From [tiiuae/cpedict](https://github.com/tiiuae/cpedict): all `(vendor, product)` pairs in NVD. Build in-memory indexes (vendor set, vendor → products, token → vendors).

## Step 3 — Match SWDB to CPE

Two stages: resolve vendor first, then product within that vendor's set. Six strategies in order; first match wins.

| Strategy | Rule | Score | Example |
|---|---|---|---|
| **exact** | identical | 1.00 | `fortinet` = `fortinet` |
| **exact_flat** | identical without underscores | 0.95 | `check_point` = `checkpoint` |
| **jaccard** | shared tokens / total tokens | 0.30–1.00 | `cisco_systems` ∩ `cisco` = 0.50 |
| **substring** | one contained in the other | 0.70 | `apache` ⊂ `apache_software_foundation` |
| **levenshtein** | char edit distance | 0.45–0.80 | `dtm` vs `air` = 0.60 (wrong, both 3 chars) |
| **token_index** | any shared token | 0.40 | `Apache Tomcat` shares `apache` |

## Step 4 — Score assignment

Scores are **automatic, not manual**. The vendor and the product are matched **separately** — each one gets its own score from the strategy that worked for it. Then we average them.

`cpe_match_score = (vendor_score + product_score) / 2`

Example for "Cisco Systems Inc — Cisco Jabber":

| Step | Result | Strategy | Score |
|---|---|---|---|
| Match vendor `cisco_systems` | → `cisco` | substring | 0.70 |
| Match product `cisco_jabber` | → `jabber` | jaccard | 1.00 |
| **Final** `cpe_match_score` | | | **0.85** |

Score interpretation:

| Range | Meaning |
|---|---|
| ≥ 0.90 | trust |
| 0.70 – 0.90 | usually correct |
| 0.50 – 0.70 | review (false positive zone, e.g. Adobe DTM → adobe_air) |
| < 0.50 | revert to naive mapping |
| 0.00 | no CPE exists in NVD |

---

# How we found CVEs for each CPE

Three tiers, tried in order. CVEs deduplicated across tiers.

| Tier | Method | Query | Reliability |
|---|---|---|---|
| **1** | `virtualMatchString` | CPE pattern matched against CVE's official CPE configs | Maximum |
| **2** | `keyword_vendor_product` | "vendor product" in CVE description text | ⚠️ Medium |
| **3** | `keyword_product_only` | "product" alone in CVE description | 🔴 Low |

## Tier examples

| Tier | Good match | Bad match |
|---|---|---|
| 1 | `cpe:2.3:*:checkpoint:quantum_security_gateway_firmware:*` → CVE-2024-24919 | (Tier 1 doesn't produce false positives) |
| 2 | `Apache Solr` → CVE about "Apache Solr SQL injection" | `Check Point VPN` → CVE about Cisco VPN |
| 3 | `Solr` → CVE about Solr | `VPN` → 800+ unrelated CVEs |
