"""
06_group_vendor_OR.py
Table 7: Per-group vendor associations vs other ransomware victims.
Fisher's exact test with BH correction.
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *
from statsmodels.stats.multitest import multipletests

df = load_ransomware()
N = len(df)

victim_vend = count_per_victim(df, 'vendors')
min_prevalence = 0.03
common_vendors = [v for v, c in victim_vend.items() if c >= int(N * min_prevalence)]
top_groups = df['group_name'].value_counts()
top_groups = top_groups[top_groups >= 50].index.tolist()

print(f"Groups: {len(top_groups)}, Vendors tested: {len(common_vendors)}")

all_results = []
for group in top_groups:
    in_group = df['group_name'] == group
    n_g = in_group.sum()

    g_vend = Counter()
    for vends in df[in_group]['vendors']:
        for v in vends: g_vend[v] += 1

    g_res = []
    for vend in common_vendors:
        a = g_vend.get(vend, 0)
        if a < 3: continue
        b = n_g - a
        c = victim_vend[vend] - a
        d = (N - n_g) - c
        if c <= 0 or d <= 0: continue
        OR, ci_lo, ci_hi, p = fisher_or(a, b, c, d)
        g_res.append({
            'group': group, 'vendor': vend,
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
    for _, r in over.head(8).iterrows():
        print(f"  {str(r['vendor'])[:29]:<30} a={r['a']:>4} b={r['b']:>4} c={r['c']:>5} d={r['d']:>5} | {r['grp_pct']:>5.1f}% vs {r['oth_pct']:>5.1f}% | OR={r['OR']:.2f} p={r['p_adj']:.4f}")
    if len(under) > 0:
        print(f"  --- underrepresented ---")
        for _, r in under.head(3).iterrows():
            print(f"  {str(r['vendor'])[:29]:<30} a={r['a']:>4} b={r['b']:>4} c={r['c']:>5} d={r['d']:>5} | {r['grp_pct']:>5.1f}% vs {r['oth_pct']:>5.1f}% | OR={r['OR']:.2f} p={r['p_adj']:.4f}")

full = pd.concat(all_results, ignore_index=True)
full.to_csv('output/A6_group_vendor_OR.csv', index=False)
print(f"\nSaved {len(full)} rows")
