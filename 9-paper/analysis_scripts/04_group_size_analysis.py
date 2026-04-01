"""
04_group_size_analysis.py
Table 4: Revenue, employees, and IT spending per group.
Uses Mann-Whitney U test to compare each group vs all other victims.
"""
import sys; sys.path.insert(0, '.')
from s00_load_data import *

df = load_ransomware()
N = len(df)

top_groups = df['group_name'].value_counts().head(20).index
overall_med_rev = df['account_revenue_usd'].median()
overall_med_emp = df['account_employees'].median()
overall_med_it = df['total_it_spend'].median()

print(f"Overall medians: Revenue=${overall_med_rev:,.0f}, Employees={overall_med_emp:.0f}, IT Spend=${overall_med_it:,.0f}")
print(f"\n{'Group':<16} {'N':>5} {'Med Revenue':>14} {'Med Empl':>10} {'Med IT Spend':>14} {'p(rev)':>10} {'p(emp)':>10} {'p(IT)':>10}")
print("-" * 95)

results = []
for g in top_groups:
    gd = df[df['group_name'] == g]
    rest = df[df['group_name'] != g]
    med_r = gd['account_revenue_usd'].median()
    med_e = gd['account_employees'].median()
    med_it = gd['total_it_spend'].median()

    _, p_rev = mannwhitneyu(gd['account_revenue_usd'].dropna(), rest['account_revenue_usd'].dropna())
    _, p_emp = mannwhitneyu(gd['account_employees'].dropna(), rest['account_employees'].dropna())
    _, p_it = mannwhitneyu(gd['total_it_spend'].dropna(), rest['total_it_spend'].dropna())

    sig = lambda p: "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "ns"
    print(f"{g:<16} {len(gd):>5} ${med_r:>12,.0f} {med_e:>10,.0f} ${med_it:>12,.0f} {p_rev:>8.4f} {sig(p_rev):>2} {p_emp:>8.4f} {sig(p_emp):>2} {p_it:>8.4f} {sig(p_it):>2}")

    results.append({
        'group': g, 'n': len(gd),
        'med_revenue': med_r, 'med_employees': med_e, 'med_it_spend': med_it,
        'mean_revenue': gd['account_revenue_usd'].mean(),
        'mean_employees': gd['account_employees'].mean(),
        'mean_it_spend': gd['total_it_spend'].mean(),
        'p_revenue': p_rev, 'p_employees': p_emp, 'p_it_spend': p_it
    })

pd.DataFrame(results).to_csv('output/A4_group_size_stats.csv', index=False)
print(f"\nSaved")
