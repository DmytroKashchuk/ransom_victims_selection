# Ransomware Technology Targeting Analysis — Scripts

## Setup

```bash
pip install pandas numpy scipy statsmodels matplotlib
mkdir -p data output
```

Place your data files in `data/`:
- `Result_79_part1.csv` — ransomware victim data (part 1)
- `Result_79_part2_csv.csv` — ransomware victim data (part 2, no header)
- `202303_Tech_Install_Universe_Counts.csv` — SWDB install universe

Edit paths in `s00_load_data.py` if your filenames differ.

## Scripts

| Script | Output | Paper Table |
|--------|--------|-------------|
| `01_category_OR_universe.py` | `A1_category_OR_universe.csv` | Table 2: Category OR vs universe |
| `02_vendor_OR_universe.py` | `A2_vendor_OR_universe.csv` | Table 3: Vendor OR vs universe |
| `03_product_OR_universe.py` | `A3_product_OR_universe.csv` | Table 5: Product (vendor,product) OR vs universe |
| `04_group_size_analysis.py` | `A4_group_size_stats.csv` | Table 4: Revenue/Employees/IT Spend per group |
| `05_group_category_OR.py` | `A5_group_category_OR.csv` | Table 8: Per-group category OR (vs other victims) |
| `06_group_vendor_OR.py` | `A6_group_vendor_OR.csv` | Table 7: Per-group vendor OR (vs other victims) |
| `07_group_product_OR.py` | `A7_group_product_OR.csv` | Table 6: Per-group product OR (vs other victims) |
| `08_figures.py` | `fig1-4.png` | All paper figures |

## Run all

```bash
python 01_category_OR_universe.py
python 02_vendor_OR_universe.py
python 03_product_OR_universe.py
python 04_group_size_analysis.py
python 05_group_category_OR.py
python 06_group_vendor_OR.py
python 07_group_product_OR.py
python 08_figures.py
```

## Methodology

All scripts use the same approach:
1. **2×2 contingency table**: a (has feature & in group), b (no feature & in group), c (has feature & not in group), d (no feature & not in group)
2. **Fisher's exact test** (two-sided) for OR and p-value
3. **Woolf's logit method** with 0.5 continuity correction for 95% CI
4. **Benjamini-Hochberg** correction (α = 0.05) for per-group analyses
5. **Mann-Whitney U** test for continuous variables (revenue, employees)

### Important: Product matching
Scripts 03 and 07 match on `(Vendor, Product)` pairs, NOT product name alone.
This avoids conflating generic names like "CRM" across vendors (e.g., Epiphany CRM = 46 victims, Saleslogix CRM = 78 — name-only matching would incorrectly report 301).

### Universe size
The SWDB universe does not publish a total enterprise count. We estimate N = 10M.
Sensitivity analysis (5M–20M) confirms relative OR rankings are stable.
