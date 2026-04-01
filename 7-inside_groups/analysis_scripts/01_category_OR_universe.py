"""
01_category_OR_universe.py
Table 2: Category-level odds ratios — ransomware victims vs enterprise universe.
For each category, builds 2x2 table:
    a = victims using category, b = victims not using it
    c = universe using it (minus a), d = universe not using it (minus b)
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *

df = load_ransomware()
univ = load_universe()
N = len(df)

victim_cat = count_per_victim(df, 'categories')
univ_cat = univ.groupby('ProductCategory')['Total Enterprises'].max().to_dict()

results = []
for cat, v_count in victim_cat.items():
    u = univ_cat.get(cat, 0)
    if u < 100 or v_count < 20:
        continue
    a = v_count
    b = N - a
    c = max(int(u) - a, 1)
    d = max(N_UNIVERSE - int(u) - b, 1)
    OR, ci_lo, ci_hi, p = fisher_or(a, b, c, d)
    results.append({
        'category': cat,
        'a': a, 'b': b, 'c': c, 'd': d,
        'victims_pct': a / N * 100,
        'universe_pct': u / N_UNIVERSE * 100,
        'OR': OR, 'ci_lo': ci_lo, 'ci_hi': ci_hi, 'p': p
    })

res = pd.DataFrame(results).sort_values('OR', ascending=False)

print(f"{'Category':<40} {'a':>5} {'b':>5} {'c':>8} {'Vic%':>6} {'Univ%':>6} {'OR':>7} {'95% CI':>18} {'p':>10}")
print("-" * 110)
for _, r in res.head(30).iterrows():
    ci = f"[{r['ci_lo']:.1f}-{r['ci_hi']:.1f}]"
    print(f"{r['category'][:39]:<40} {r['a']:>5} {r['b']:>5} {r['c']:>8} {r['victims_pct']:>5.1f}% {r['universe_pct']:>5.2f}% {r['OR']:>7.1f} {ci:>18} {r['p']:>10.1e}")

res.to_csv('output/A1_category_OR_universe.csv', index=False)
print(f"\nSaved {len(res)} rows to output/A1_category_OR_universe.csv")
