"""
Extract every website (URL or bare domain) mentioned in the Black Basta
chat leak.

Output: one row per (normalized_domain), with:
  - domain               : normalized hostname (lowercase, no port, no path)
  - count                : total number of mentions
  - n_unique_msgs        : distinct messages mentioning it
  - n_unique_senders     : distinct sender_alias values
  - n_unique_chats       : distinct chat_id values
  - first_seen           : earliest timestamp
  - last_seen            : latest timestamp
  - senders              : pipe-separated sender aliases
  - msg_ids              : pipe-separated msg_id values (chat_id@timestamp)
  - sample_full_urls     : up to 5 distinct full-URL forms seen (with path),
                           for context when the same host has many paths
  - had_scheme           : True if at least one mention had http(s):// scheme

No filtering of "internal" infrastructure (e.g. matrix.bestflowers247.online).
The analyst decides downstream what to keep.

Dependencies: pandas, tqdm, plus the existing iter_messages loader from
level1_lexicon_match.py (handles the Black Basta pseudo-JSON format).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from tqdm import tqdm

# Reuse the robust loader from the lexicon-matching script.
sys.path.insert(0, str(Path(__file__).parent))
from level1_lexicon_match import iter_messages  # noqa: E402


# ---------------------------------------------------------------------------
# Iteration with metadata
# ---------------------------------------------------------------------------
# iter_messages from level1 only yields (msg_id, body). We need timestamp
# and sender_alias too, so we re-implement a metadata-aware iterator that
# uses the same parsing logic but yields full records.

import json  # noqa: E402
from level1_lexicon_match import _parse_blackbasta_pseudo_json, BODY_FIELDS  # noqa: E402


def iter_messages_with_meta(chats_json: Path):
    """
    Yield dicts with at least: chat_id, sender_alias, timestamp, message.
    Falls back gracefully across the same 4 file shapes as iter_messages.
    """
    print(f"Loading {chats_json} ...", file=sys.stderr)
    raw = chats_json.read_text(encoding="utf-8")

    def _yield_dict(obj, default_idx):
        if not isinstance(obj, dict):
            return None
        body = next((obj[f] for f in BODY_FIELDS if f in obj and obj[f]), "")
        return {
            "chat_id": obj.get("chat_id", ""),
            "sender_alias": obj.get("sender_alias", ""),
            "timestamp": obj.get("timestamp", ""),
            "message": body,
            "msg_id": (
                f"{obj['chat_id']}@{obj['timestamp']}"
                if "chat_id" in obj and "timestamp" in obj
                else str(default_idx)
            ),
        }

    # 1) standard JSON
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            for i, (_, obj) in enumerate(data.items()):
                rec = _yield_dict(obj, i)
                if rec:
                    yield rec
            return
        if isinstance(data, list):
            for i, obj in enumerate(data):
                rec = _yield_dict(obj, i)
                if rec:
                    yield rec
            return
    except json.JSONDecodeError:
        pass

    # 2) NDJSON
    parsed = []
    ok = True
    for lineno, line in enumerate(raw.splitlines()):
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]", "{", "}"):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                parsed.append((lineno, obj))
        except json.JSONDecodeError:
            ok = False
            break
    if ok and parsed:
        for lineno, obj in parsed:
            rec = _yield_dict(obj, lineno)
            if rec:
                yield rec
        return

    # 3) concatenated JSON values
    decoder = json.JSONDecoder()
    idx = 0
    counter = 0
    n = len(raw)
    raw_decode_results = []
    raw_decode_ok = True
    while idx < n:
        while idx < n and raw[idx] in " \t\r\n,[]":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            raw_decode_ok = False
            break
        if isinstance(obj, dict):
            raw_decode_results.append(obj)
        idx = end
    if raw_decode_ok and raw_decode_results:
        for i, obj in enumerate(raw_decode_results):
            rec = _yield_dict(obj, i)
            if rec:
                yield rec
        return

    # 4) Black Basta pseudo-JSON
    records = _parse_blackbasta_pseudo_json(raw)
    for i, obj in enumerate(records):
        rec = _yield_dict(obj, i)
        if rec:
            yield rec


# ---------------------------------------------------------------------------
# URL / domain extraction
# ---------------------------------------------------------------------------

# Two complementary patterns. Run both per message.

# Full URLs with explicit scheme. Greedy on URL chars; stop at whitespace
# or anything that's clearly a sentence boundary in chat context.
URL_PATTERN = re.compile(
    r"""
    https?://                               # scheme
    [^\s<>\"\'`,()\[\]{}]+                  # URL body (stop at whitespace
                                            # or common chat punctuation)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Bare domains: at least one dot, last segment a plausible TLD.
# We use \b boundaries and a TLD whitelist (post-filter) for precision.
BARE_DOMAIN_PATTERN = re.compile(
    r"""
    (?<![\w./-])                            # not preceded by alphanumeric,
                                            # dot, slash, hyphen — kills
                                            # path fragments (we handle
                                            # email LHS separately below)
    (?:[a-z0-9][a-z0-9\-]{0,62}\.)+         # one or more labels + dots
    [a-z]{2,24}                             # TLD: 2-24 letters
    (?![/\w-])                              # not followed by alphanumeric/path
                                            # (paths handled by URL_PATTERN)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Email pattern — capture both LHS and domain. The domain is the
# interesting part (might be a victim org).
EMAIL_PATTERN = re.compile(
    r"""
    \b
    [a-z0-9._%+-]+                          # local-part
    @
    ([a-z0-9][a-z0-9\-]{0,62}               # domain first label
     (?:\.[a-z0-9][a-z0-9\-]{0,62})*        # additional labels
     \.[a-z]{2,24})                         # TLD
    \b
    """,
    re.VERBOSE | re.IGNORECASE,
)

# IPv4 pattern. Tracked separately from domains because IPs are usually
# C2/infrastructure rather than victim sites — different downstream use.
IPV4_PATTERN = re.compile(
    r"""
    (?<![\w.])
    (?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}
    (?:25[0-5]|2[0-4]\d|[01]?\d\d?)
    (?![\w.])
    """,
    re.VERBOSE,
)

# File extensions that look like TLDs but aren't. If the "TLD" portion
# matches one of these, the candidate is dropped.
FILE_EXT_TLDS: frozenset[str] = frozenset({
    "exe", "dll", "sys", "bin", "dat", "iso", "img",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
    "zip", "rar", "tar", "gz", "7z", "bz2", "xz",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp",
    "mp3", "mp4", "avi", "mkv", "mov", "wav", "flac", "ogg",
    "json", "xml", "yaml", "yml", "csv", "log", "ini", "cfg", "conf",
    "py", "js", "ts", "go", "rs", "rb", "php", "html", "htm", "css",
    "sh", "bat", "ps1", "cmd", "vbs",
    "sql", "db", "sqlite",
    "ovpn", "key", "pem", "crt", "cer",
    "bak", "tmp", "old", "new",
})

# IANA "common TLDs" — a positive whitelist would be enormous; instead we
# use a small denylist of obviously non-TLDs (above) and trust the regex.
# The 2-24 letter constraint already excludes most accidents.


def normalize_host(host: str) -> str:
    """Lowercase, strip port, strip leading 'www.'."""
    host = host.lower().strip()
    # strip port
    if ":" in host:
        host = host.split(":", 1)[0]
    # strip trailing dot
    host = host.rstrip(".")
    return host


def extract_websites(text: str) -> tuple[list[tuple[str, str, bool]], list[str]]:
    """
    Extract websites and IPs from a single message body.

    Returns:
      websites: list of (normalized_host, full_form_seen, had_scheme)
      ips:      list of IPv4 addresses (deduped within message)

    full_form_seen is the URL with path if present, else just the host.
    had_scheme is True if the original mention had http(s)://.
    """
    if not isinstance(text, str) or not text:
        return [], []

    found: list[tuple[str, str, bool]] = []
    ips: list[str] = []
    masked = text  # mask already-extracted spans so passes don't double-count

    def _is_ipv4(s: str) -> bool:
        labels = s.split(".")
        return len(labels) == 4 and all(l.isdigit() for l in labels)

    # 1) URLs with scheme
    for m in URL_PATTERN.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        try:
            parsed = urlparse(url)
            host = normalize_host(parsed.netloc)
            if not host or "." not in host:
                continue
            # IPv4 host -> ips bucket, not domains
            if _is_ipv4(host):
                ips.append(host)
                start, end = m.span()
                masked = masked[:start] + (" " * (end - start)) + masked[end:]
                continue
            tld = host.rsplit(".", 1)[-1].lower()
            if tld in FILE_EXT_TLDS:
                continue
            found.append((host, url, True))
            start, end = m.span()
            masked = masked[:start] + (" " * (end - start)) + masked[end:]
        except ValueError:
            continue

    # 2) email addresses — extract domain part
    for m in EMAIL_PATTERN.finditer(masked):
        domain = normalize_host(m.group(1))
        if not domain or "." not in domain:
            continue
        tld = domain.rsplit(".", 1)[-1]
        if tld in FILE_EXT_TLDS:
            continue
        # full_form: keep the whole email as context (so analyst can see it
        # came from an email rather than a URL)
        found.append((domain, m.group(0), False))
        # mask the whole email span so bare-domain pass doesn't re-extract
        start, end = m.span()
        masked = masked[:start] + (" " * (end - start)) + masked[end:]

    # 3) bare domains (in the masked text)
    for m in BARE_DOMAIN_PATTERN.finditer(masked):
        candidate = m.group(0).rstrip(".,;:!?)").lower()
        if not candidate:
            continue
        tld = candidate.rsplit(".", 1)[-1]
        if tld in FILE_EXT_TLDS:
            continue
        host = normalize_host(candidate)
        if not host or "." not in host:
            continue
        if _is_ipv4(host):
            continue  # extremely unlikely to reach here, but safe
        found.append((host, host, False))

    # 4) bare IPv4
    for m in IPV4_PATTERN.finditer(masked):
        ips.append(m.group(0))

    # dedupe IPs within message
    ips = list(dict.fromkeys(ips))

    return found, ips


def load_known_victims(victims_csv: Path) -> set[str]:
    """
    Load the ransomware.live victims CSV and return a set of normalized
    victim domains.

    Pulls candidates from two columns ('Post Title' and 'Website') because
    the data is inconsistent — sometimes the domain is in one, sometimes
    the other, sometimes both.
    """
    df = pd.read_csv(victims_csv)
    victims: set[str] = set()
    for col in ("Post Title", "Website"):
        if col not in df.columns:
            continue
        for raw in df[col].dropna():
            v = str(raw).strip().lower()
            if not v:
                continue
            # tolerate values like "www.memc.com" or "https://memc.com/"
            v = v.removeprefix("http://").removeprefix("https://")
            v = v.split("/", 1)[0]      # strip path
            v = v.split(":", 1)[0]      # strip port
            v = v.removeprefix("www.")
            v = v.rstrip(".")
            # must look like a domain
            if "." in v and " " not in v:
                victims.add(v)
    print(
        f"Loaded {len(victims):,} known victim domains from {victims_csv.name}",
        file=sys.stderr,
    )
    return victims


def is_hacked(domain: str, victims: set[str]) -> bool:
    """
    True if the domain is a known victim, OR a subdomain of one.
    Example: 'vpn.memc.com' matches victim 'memc.com'.
    Implementation: walk the domain's suffix chain and check membership.
    """
    if not domain or not victims:
        return False
    if domain in victims:
        return True
    # check parent suffixes: vpn.memc.com -> memc.com -> com
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):  # skip TLD-only
        suffix = ".".join(parts[i:])
        if suffix in victims:
            return True
    return False


# ---------------------------------------------------------------------------
# Main aggregation
# ---------------------------------------------------------------------------

def aggregate(
    chats_json: Path,
    known_victims: set[str] | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Scan all messages, extract websites and IPs, aggregate per host/IP.

    If known_victims is provided, the websites_df gets a 'hacked' column
    that is True when the domain (or any of its parent domains) is in the set.

    Returns (websites_df, ips_df).
    """

    # per-host accumulator
    hosts: dict[str, dict] = defaultdict(lambda: {
        "count": 0,
        "msg_ids": set(),
        "senders": set(),
        "chat_ids": set(),
        "timestamps": [],
        "full_urls": set(),
        "had_scheme": False,
    })
    # per-IP accumulator (same shape, simpler)
    ips_acc: dict[str, dict] = defaultdict(lambda: {
        "count": 0,
        "msg_ids": set(),
        "senders": set(),
        "chat_ids": set(),
        "timestamps": [],
    })

    n_msgs = 0
    n_msgs_with_url = 0
    n_msgs_with_ip = 0
    for rec in tqdm(iter_messages_with_meta(chats_json), desc="Scanning messages"):
        n_msgs += 1
        body = rec["message"]
        websites, ips = extract_websites(body)
        if websites:
            n_msgs_with_url += 1
        if ips:
            n_msgs_with_ip += 1

        seen_in_msg: set[str] = set()
        for host, full_form, had_scheme in websites:
            h = hosts[host]
            h["count"] += 1
            if host not in seen_in_msg:
                h["msg_ids"].add(rec["msg_id"])
                if rec["sender_alias"]:
                    h["senders"].add(rec["sender_alias"])
                if rec["chat_id"]:
                    h["chat_ids"].add(rec["chat_id"])
                if rec["timestamp"]:
                    h["timestamps"].append(rec["timestamp"])
                seen_in_msg.add(host)
            h["full_urls"].add(full_form)
            if had_scheme:
                h["had_scheme"] = True

        for ip in ips:
            entry = ips_acc[ip]
            entry["count"] += 1
            entry["msg_ids"].add(rec["msg_id"])
            if rec["sender_alias"]:
                entry["senders"].add(rec["sender_alias"])
            if rec["chat_id"]:
                entry["chat_ids"].add(rec["chat_id"])
            if rec["timestamp"]:
                entry["timestamps"].append(rec["timestamp"])

    print(
        f"\nScanned {n_msgs:,} messages.\n"
        f"  {n_msgs_with_url:,} ({n_msgs_with_url/max(n_msgs,1):.1%}) had at least one URL/domain.\n"
        f"  {n_msgs_with_ip:,} ({n_msgs_with_ip/max(n_msgs,1):.1%}) had at least one IPv4.",
        file=sys.stderr,
    )
    print(f"Distinct hosts: {len(hosts):,}", file=sys.stderr)
    print(f"Distinct IPs:   {len(ips_acc):,}", file=sys.stderr)

    # websites df
    rows = []
    for host, h in hosts.items():
        ts = sorted(h["timestamps"])
        sample_urls = sorted(h["full_urls"])[:5]
        rows.append({
            "domain": host,
            "hacked": is_hacked(host, known_victims) if known_victims else False,
            "count": h["count"],
            "n_unique_msgs": len(h["msg_ids"]),
            "n_unique_senders": len(h["senders"]),
            "n_unique_chats": len(h["chat_ids"]),
            "first_seen": ts[0] if ts else "",
            "last_seen": ts[-1] if ts else "",
            "had_scheme": h["had_scheme"],
            "senders": "|".join(sorted(h["senders"])),
            "sample_full_urls": " | ".join(sample_urls),
            "msg_ids": "|".join(sorted(h["msg_ids"])),
        })
    websites_df = pd.DataFrame(rows).sort_values(
        ["hacked", "n_unique_msgs", "count"], ascending=[False, False, False]
    ).reset_index(drop=True)

    # ips df
    ip_rows = []
    for ip, entry in ips_acc.items():
        ts = sorted(entry["timestamps"])
        ip_rows.append({
            "ip": ip,
            "count": entry["count"],
            "n_unique_msgs": len(entry["msg_ids"]),
            "n_unique_senders": len(entry["senders"]),
            "n_unique_chats": len(entry["chat_ids"]),
            "first_seen": ts[0] if ts else "",
            "last_seen": ts[-1] if ts else "",
            "senders": "|".join(sorted(entry["senders"])),
            "msg_ids": "|".join(sorted(entry["msg_ids"])),
        })
    if ip_rows:
        ips_df = pd.DataFrame(ip_rows).sort_values(
            ["n_unique_msgs", "count"], ascending=False
        ).reset_index(drop=True)
    else:
        ips_df = pd.DataFrame(columns=[
            "ip", "count", "n_unique_msgs", "n_unique_senders",
            "n_unique_chats", "first_seen", "last_seen", "senders", "msg_ids",
        ])

    return websites_df, ips_df


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--chats",
        default="blackbasta_chats.json",
        help="Path to blackbasta_chats.json",
    )
    ap.add_argument(
        "--victims",
        default=None,
        help=(
            "Optional path to ransomware.live victims CSV "
            "(columns: 'Post Title', 'Website'). "
            "If provided, adds a 'hacked' column to the websites output."
        ),
    )
    ap.add_argument(
        "--out",
        default="blackbasta_websites.csv",
        help="Output CSV for websites: one row per (normalized) domain",
    )
    ap.add_argument(
        "--out-ips",
        default="blackbasta_ips.csv",
        help="Output CSV for IPv4 addresses: one row per IP",
    )
    args = ap.parse_args()

    known_victims = None
    if args.victims:
        known_victims = load_known_victims(Path(args.victims))

    websites_df, ips_df = aggregate(Path(args.chats), known_victims)

    out = Path(args.out)
    websites_df.to_csv(out, index=False)
    print(f"\nWrote {len(websites_df):,} rows -> {out}", file=sys.stderr)

    out_ips = Path(args.out_ips)
    ips_df.to_csv(out_ips, index=False)
    print(f"Wrote {len(ips_df):,} rows -> {out_ips}", file=sys.stderr)

    if known_victims is not None:
        n_hacked = int(websites_df["hacked"].sum())
        print(
            f"\nMatched {n_hacked:,} domains against known Black Basta victims.",
            file=sys.stderr,
        )

    print("\nTop 30 hosts by unique-message mentions:", file=sys.stderr)
    cols = ["domain", "count", "n_unique_msgs", "n_unique_senders",
            "n_unique_chats", "first_seen", "last_seen"]
    if "hacked" in websites_df.columns:
        cols.insert(1, "hacked")
    print(
        websites_df.head(30)[cols].to_string(index=False),
        file=sys.stderr,
    )

    if len(ips_df):
        print("\nTop 20 IPs by unique-message mentions:", file=sys.stderr)
        print(
            ips_df.head(20)[
                ["ip", "count", "n_unique_msgs", "n_unique_senders", "first_seen", "last_seen"]
            ].to_string(index=False),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()