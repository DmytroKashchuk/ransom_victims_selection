"""
07_group_product_OR.py
Table 6: Per-group product associations vs other ransomware victims.
Products matched on (vendor, product) pairs.
Fisher's exact test with BH correction.
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *
from statsmodels.stats.multitest import multipletests

df = load_ransomware()
N = len(df)

# Count victims per (vendor, product) pair
victim_pairs = Counter()
for pairs in df['pairs']:
    for p in pairs:
        victim_pairs[p] += 1

# Only test products present in >=50 victims (~1%)
common_prods = [p for p, c in victim_pairs.items() if c >= 50]
top_groups = df['group_name'].value_counts()
top_groups = top_groups[top_groups >= 50].index.tolist()

print(f"Groups: {len(top_groups)}, Products tested: {len(common_prods)}")

all_results = []
for group in top_groups:
    in_group = df['group_name'] == group
    n_g = in_group.sum()

    g_pairs = Counter()
    for pairs in df[in_group]['pairs']:
        for p in pairs:
            g_pairs[p] += 1

    g_res = []
    for prod in common_prods:
        a = g_pairs.get(prod, 0)
        if a < 5: continue
        b = n_g - a
        c = victim_pairs[prod] - a
        d = (N - n_g) - c
        if c <= 0 or d <= 0: continue
        OR, ci_lo, ci_hi, p = fisher_or(a, b, c, d)
        g_res.append({
            'group': group, 'vendor': prod[0], 'product': prod[1],
            'a': a, 'b': b, 'c': c, 'd': d,
            'grp_pct': a/n_g*100, 'oth_pct': c/(N-n_g)*100,
            'OR': OR, 'ci_lo': ci_lo, 'ci_hi': ci_hi, 'p': p
        })

    if not g_res: continue
    gdf = pd.DataFrame(g_res)
    reject, padj, _, _ = multipletests(gdf['p'], method='fdr_bh', alpha=0.05)
    gdf['p_adj'] = padj
    gdf['significant'] = reject
    all_results.append(gdf)

    over = gdf[(gdf['significant']) & (gdf['OR'] > 1)].sort_values('OR', ascending=False)
    under = gdf[(gdf['significant']) & (gdf['OR'] < 1)].sort_values('OR')
    print(f"\n--- {group} ({n_g} victims) | {len(over)} over, {len(under)} under ---")
    for _, r in over.head(10).iterrows():
        print(f"  {str(r['vendor'])[:15]:<16} {str(r['product'])[:20]:<21} a={r['a']:>4} b={r['b']:>4} c={r['c']:>5} d={r['d']:>5} | {r['grp_pct']:>5.1f}% vs {r['oth_pct']:>5.1f}% | OR={r['OR']:.2f} p={r['p_adj']:.4f}")

full = pd.concat(all_results, ignore_index=True)
full.to_csv('output/A7_group_product_OR.csv', index=False)
print(f"\nSaved {len(full)} rows")
