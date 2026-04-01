"""
00_load_data.py
Shared data loading module. All other scripts import from here.
"""
import pandas as pd
import numpy as np
import json
from collections import Counter, defaultdict
from scipy.stats import fisher_exact, mannwhitneyu
import warnings
warnings.filterwarnings('ignore')

# ── Paths (adjust to your environment) ──
PATH_PART1 = 'data/Result_79_part1.csv'
PATH_PART2 = 'data/Result_79_part2_csv.csv'
PATH_UNIVERSE = 'data/202303_Tech_Install_Universe_Counts.csv'

N_UNIVERSE = 5620161  # estimated total SWDB enterprises
5620161

def load_ransomware(path1=PATH_PART1, path2=PATH_PART2):
    df1 = pd.read_csv(path1)
    df2 = pd.read_csv(path2, header=None, names=df1.columns)
    df = pd.concat([df1, df2], ignore_index=True)
    df['tech_parsed'] = df['technologies'].apply(_parse_tech)
    df['categories'] = df['tech_parsed'].apply(lambda ts: set(t.get('category','') for t in ts))
    df['vendors'] = df['tech_parsed'].apply(lambda ts: set(t.get('vendor','') for t in ts))
    df['pairs'] = df['tech_parsed'].apply(lambda ts: set((t.get('vendor','').strip(), t.get('product','').strip()) for t in ts))
    df['total_it_spend'] = (df['account_hw_spending'].fillna(0) + df['account_sw_spending'].fillna(0) +
                            df['account_it_services_spending'].fillna(0) + df['account_ict_spending'].fillna(0))
    return df

def load_universe(path=PATH_UNIVERSE):
    univ = pd.read_csv(path, encoding='latin-1')
    univ = univ[univ['Total Sites'] != 'Total Sites']
    for c in ['Total Sites','US Sites','Total Enterprises','Enterprises in US']:
        univ[c] = univ[c].astype(str).str.replace(',','').astype(float)
    univ = univ.drop_duplicates(subset=['Product','VendorName'])
    return univ

def _parse_tech(t):
    if pd.isna(t): return []
    t = t.replace('""', '"')
    if t.startswith('"') and t.endswith('"'): t = t[1:-1]
    return json.loads(t)

def fisher_or(a, b, c, d):
    """Compute OR, 95% CI (Woolf), and p-value via Fisher's exact test."""
    OR, p = fisher_exact([[a, b], [c, d]], alternative='two-sided')
    aa, bb, cc, dd = a+0.5, b+0.5, c+0.5, d+0.5
    log_or = np.log(aa*dd / (bb*cc))
    se = np.sqrt(1/aa + 1/bb + 1/cc + 1/dd)
    ci_lo = np.exp(log_or - 1.96*se)
    ci_hi = np.exp(log_or + 1.96*se)
    return OR, ci_lo, ci_hi, p

def count_per_victim(df, field):
    """Count how many victims have each unique value in field (set column)."""
    counts = Counter()
    for vals in df[field]:
        for v in vals:
            counts[v] += 1
    return counts

if __name__ == '__main__':
    df = load_ransomware()
    univ = load_universe()
    print(f"Ransomware: {len(df)} victims, {df['group_name'].nunique()} groups")
    print(f"Universe: {len(univ)} unique (vendor,product) pairs")
