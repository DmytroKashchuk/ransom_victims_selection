"""
02_vendor_OR_universe.py
Table 3: Vendor-level odds ratios — ransomware victims vs enterprise universe.
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *

df = load_ransomware()
univ = load_universe()
N = len(df)

victim_vend = count_per_victim(df, 'vendors')
univ_vend = univ.groupby('VendorName')['Total Enterprises'].max().to_dict()

results = []
for vend, v_count in victim_vend.items():
    u = univ_vend.get(vend, 0)
    if u < 100 or v_count < 20:
        continue
    a = v_count
    b = N - a
    c = max(int(u) - a, 1)
    d = max(N_UNIVERSE - int(u) - b, 1)
    OR, ci_lo, ci_hi, p = fisher_or(a, b, c, d)
    results.append({
        'vendor': vend,
        'a': a, 'b': b, 'c': c, 'd': d,
        'victims_pct': a / N * 100,
        'universe_pct': u / N_UNIVERSE * 100,
        'OR': OR, 'ci_lo': ci_lo, 'ci_hi': ci_hi, 'p': p
    })

res = pd.DataFrame(results).sort_values('OR', ascending=False)

print("=== TOP 25 HIGHEST OR ===")
print(f"{'Vendor':<35} {'a':>5} {'b':>5} {'c':>8} {'Vic%':>6} {'Univ%':>6} {'OR':>7} {'95% CI':>18}")
print("-" * 100)
for _, r in res.head(25).iterrows():
    ci = f"[{r['ci_lo']:.1f}-{r['ci_hi']:.1f}]"
    print(f"{r['vendor'][:34]:<35} {r['a']:>5} {r['b']:>5} {r['c']:>8} {r['victims_pct']:>5.1f}% {r['universe_pct']:>5.2f}% {r['OR']:>7.1f} {ci:>18}")

print(f"\n=== LOWEST OR (>=50 victims) ===")
low = res[res['a'] >= 50].sort_values('OR')
for _, r in low.head(15).iterrows():
    ci = f"[{r['ci_lo']:.1f}-{r['ci_hi']:.1f}]"
    print(f"{r['vendor'][:34]:<35} {r['a']:>5} {r['b']:>5} {r['c']:>8} {r['victims_pct']:>5.1f}% {r['universe_pct']:>5.2f}% {r['OR']:>7.1f} {ci:>18}")

res.to_csv('output/A2_vendor_OR_universe.csv', index=False)
print(f"\nSaved {len(res)} rows")
