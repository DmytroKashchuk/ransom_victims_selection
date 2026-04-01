"""
08_figures.py
Generate all figures for the paper.
Reads CSV outputs from scripts 01-07.
"""
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

import sys; sys.path.insert(0, '.')
from s00_load_data import *

df = load_ransomware()

# ── Figure 1: Victim counts ──
fig, ax = plt.subplots(figsize=(10, 5))
top20 = df['group_name'].value_counts().head(20)
ax.barh(top20.index[::-1], top20.values[::-1], color='#2c3e50', edgecolor='white')
ax.set_xlabel('Number of Victims')
ax.set_title('Ransomware Group Victim Counts (Top 20)', fontweight='bold')
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout(); plt.savefig('output/fig1_victim_counts.png', dpi=200); plt.close()

# ── Figure 2: Category OR ──
cat_df = pd.read_csv('output/A1_category_OR_universe.csv').sort_values('OR', ascending=False).head(20)
fig, ax = plt.subplots(figsize=(11, 7))
labels = cat_df['category'].values[::-1]
ors = cat_df['OR'].values[::-1]
ax.barh(labels, ors, color='#c0392b', edgecolor='white')
ax.set_xlabel('Odds Ratio')
ax.set_title('Category-Level Odds Ratios (all p < 0.001)', fontweight='bold')
ax.axvline(1, color='black', linewidth=0.8, linestyle='--', alpha=0.5)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
for bar, val in zip(ax.patches, ors):
    ax.text(val+0.3, bar.get_y()+bar.get_height()/2, f'{val:.1f}x', va='center', fontsize=7)
plt.tight_layout(); plt.savefig('output/fig2_category_OR.png', dpi=200); plt.close()

# ── Figure 3: Revenue/Employees per group ──
gs = pd.read_csv('output/A4_group_size_stats.csv').sort_values('med_revenue', ascending=False)
fig, (ax1,ax2) = plt.subplots(1, 2, figsize=(13, 5))
overall_rev = df['account_revenue_usd'].median()
overall_emp = df['account_employees'].median()

ax1.barh(gs['group'].values[::-1], (gs['med_revenue']/1e6).values[::-1], color='#2980b9', edgecolor='white')
ax1.axvline(overall_rev/1e6, color='black', linewidth=1, linestyle='--', alpha=0.6, label=f'Overall ${overall_rev/1e6:.1f}M')
ax1.set_xlabel('Median Revenue ($M)'); ax1.set_title('Median Victim Revenue', fontweight='bold')
ax1.legend(fontsize=8); ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)

ax2.barh(gs['group'].values[::-1], gs['med_employees'].values[::-1], color='#e67e22', edgecolor='white')
ax2.axvline(overall_emp, color='black', linewidth=1, linestyle='--', alpha=0.6, label=f'Overall {overall_emp:.0f}')
ax2.set_xlabel('Median Employees'); ax2.set_title('Median Victim Size', fontweight='bold')
ax2.legend(fontsize=8); ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)

plt.tight_layout(); plt.savefig('output/fig3_revenue_employees.png', dpi=200); plt.close()

# ── Figure 4: Group association direction ──
cat_or = pd.read_csv('output/A5_group_category_OR.csv')
summary = {}
for g in cat_or['group'].unique():
    sig = cat_or[(cat_or['group']==g) & (cat_or['significant']==True)]
    summary[g] = (len(sig[sig['OR']>1]), len(sig[sig['OR']<1]))

groups_s = sorted(summary.keys(), key=lambda g: summary[g][0]-summary[g][1], reverse=True)
over = [summary[g][0] for g in groups_s]
under = [-summary[g][1] for g in groups_s]

fig, ax = plt.subplots(figsize=(10, 6))
ax.barh(groups_s[::-1], over[::-1], color='#e74c3c', label='Overrepresented')
ax.barh(groups_s[::-1], under[::-1], color='#3498db', label='Underrepresented')
ax.axvline(0, color='black', linewidth=0.8)
ax.set_xlabel('Significant Category Associations (BH-adj. p < 0.05)')
ax.set_title('Direction of Group-Category Associations', fontweight='bold')
ax.legend(loc='lower right'); ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout(); plt.savefig('output/fig4_association_direction.png', dpi=200); plt.close()

print("All figures saved to output/")
