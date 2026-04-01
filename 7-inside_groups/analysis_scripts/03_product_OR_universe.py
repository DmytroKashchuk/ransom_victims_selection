"""
03_product_OR_universe.py
Table 5: Product-level odds ratios — matched on (Vendor, Product) pair.
This avoids the bug of conflating generic product names across vendors.
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *

df = load_ransomware()
univ = load_universe()
N = len(df)

# Count victims per (vendor, product) pair
victim_pairs = Counter()
for pairs in df['pairs']:
    for pair in pairs:
        victim_pairs[pair] += 1

# Build universe lookup on (vendor, product)
univ['join_key'] = univ['VendorName'].str.strip() + '|||' + univ['Product'].str.strip()
univ_lookup = dict(zip(univ['join_key'], zip(univ['Total Enterprises'], univ['ProductCategory'])))

results = []
for (vendor, product), v_count in victim_pairs.items():
    key = f"{vendor}|||{product}"
    if key not in univ_lookup:
        continue
    u, category = univ_lookup[key]
    u = int(u)
    if u < 100 or v_count < 15:
        continue
    a = v_count
    b = N - a
    c = max(u - a, 1)
    d = max(N_UNIVERSE - u - b, 1)
    OR, ci_lo, ci_hi, p = fisher_or(a, b, c, d)
    results.append({
        'product': product, 'vendor': vendor, 'category': category,
        'a': a, 'b': b, 'c': c, 'd': d,
        'victims_pct': a / N * 100,
        'universe_pct': u / N_UNIVERSE * 100,
        'OR': OR, 'ci_lo': ci_lo, 'ci_hi': ci_hi, 'p': p
    })

res = pd.DataFrame(results).sort_values('OR', ascending=False)

print(f"Total (vendor,product) pairs tested: {len(res)}")
print(f"\n=== TOP 30 HIGHEST OR ===")
print(f"{'Product':<25} {'Vendor':<18} {'Category':<22} {'a':>5} {'b':>5} {'c':>7} {'Vic%':>6} {'Univ%':>6} {'OR':>9} {'95% CI':>18}")
print("-" * 140)
for _, r in res.head(30).iterrows():
    ci = f"[{r['ci_lo']:.1f}-{r['ci_hi']:.1f}]"
    print(f"{str(r['product'])[:24]:<25} {str(r['vendor'])[:17]:<18} {str(r['category'])[:21]:<22} {r['a']:>5} {r['b']:>5} {r['c']:>7} {r['victims_pct']:>5.1f}% {r['universe_pct']:>5.3f}% {r['OR']:>9.1f} {ci:>18}")

print(f"\n=== LOWEST OR (>=30 victims) ===")
low = res[res['a'] >= 30].sort_values('OR')
for _, r in low.head(20).iterrows():
    ci = f"[{r['ci_lo']:.1f}-{r['ci_hi']:.1f}]"
    print(f"{str(r['product'])[:24]:<25} {str(r['vendor'])[:17]:<18} {str(r['category'])[:21]:<22} {r['a']:>5} {r['b']:>5} {r['c']:>7} {r['victims_pct']:>5.1f}% {r['universe_pct']:>5.3f}% {r['OR']:>9.1f} {ci:>18}")

res.to_csv('output/A3_product_OR_universe.csv', index=False)
print(f"\nSaved {len(res)} rows")
