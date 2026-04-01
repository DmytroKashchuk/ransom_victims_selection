"""
05_group_category_OR.py
Per-group category associations: Fisher's exact test vs other ransomware victims.
BH correction for multiple comparisons.
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *
from statsmodels.stats.multitest import multipletests

df = load_ransomware()
N = len(df)

victim_cat = count_per_victim(df, 'categories')
min_victims_group = 50
min_prevalence = 0.05
valid_cats = [c for c, n in victim_cat.items() if n >= int(N * min_prevalence)]
top_groups = df['group_name'].value_counts()
top_groups = top_groups[top_groups >= min_victims_group].index.tolist()

print(f"Groups: {len(top_groups)}, Categories: {len(valid_cats)}")

all_results = []
for group in top_groups:
    in_group = df['group_name'] == group
    n_g = in_group.sum()

    g_cats = Counter()
    for cats in df[in_group]['categories']:
        for c in cats: g_cats[c] += 1

    g_res = []
    for cat in valid_cats:
        a = g_cats.get(cat, 0)
        b = n_g - a
        c = victim_cat[cat] - a
        d = (N - n_g) - c
        if c <= 0 or d <= 0: continue
        OR, ci_lo, ci_hi, p = fisher_or(a, b, c, d)
        g_res.append({
            'group': group, 'category': cat,
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
        ci = f"[{r['ci_lo']:.2f}-{r['ci_hi']:.2f}]"
        print(f"  {r['category'][:35]:<36} a={r['a']:>4} b={r['b']:>4} c={r['c']:>5} d={r['d']:>5} | {r['grp_pct']:>5.1f}% vs {r['oth_pct']:>5.1f}% | OR={r['OR']:.2f} {ci} p_adj={r['p_adj']:.4f}")

full = pd.concat(all_results, ignore_index=True)
full.to_csv('output/A5_group_category_OR.csv', index=False)
print(f"\nSaved {len(full)} rows")
