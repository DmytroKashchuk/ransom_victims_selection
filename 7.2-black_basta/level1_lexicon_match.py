"""
Level 1: deterministic lexicon matching of swdb_universe products
against the Black Basta chat leak.

Pipeline:
  1. Load swdb_universe_installs.csv -> dedup (VendorName, Product) keeping
     MAX enterprises (matches the project-wide convention).
  2. Generate normalized variants per product (full name, product-only,
     significant tokens, attached/spaced forms).
  3. Drop ambiguous/short tokens via stoplist + min-length rule.
  4. Build an Aho-Corasick automaton over all variants.
  5. Stream blackbasta_chats.json, normalize each message body, scan.
  6. Post-filter matches with word-boundary check to kill substring noise
     (e.g. 'vm' inside 'vmstorage').
  7. Aggregate -> CSV: one row per product, with hit count and msg_ids list.

Dependencies: pandas, pyahocorasick, tqdm
    pip install pyahocorasick tqdm
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path

import ahocorasick
import pandas as pd
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Variant generation
# ---------------------------------------------------------------------------

# Tokens that must NEVER be emitted as a standalone variant. These are either
# generic English words that collide with everyday vocabulary, or short
# product-name fragments that match anything. Tune this list after a first
# pass on the data — it is the single biggest lever on precision.
STOPWORD_TOKENS: frozenset[str] = frozenset({
    # generic
    "the", "and", "for", "with", "your", "you", "our", "all", "any",
    # business / packaging words that appear in product names
    "server", "client", "service", "services", "system", "systems",
    "software", "solution", "solutions", "suite", "platform", "edition",
    "professional", "pro", "enterprise", "standard", "premium", "basic",
    "free", "lite", "plus", "ultimate", "express", "starter",
    "cloud", "online", "web", "desktop", "mobile", "core", "base",
    "manager", "management", "tool", "tools", "studio", "workstation",
    "office", "team", "teams", "one", "first", "next", "edge",
    "company", "corp", "corporation", "inc", "ltd", "llc", "gmbh",
    "data", "file", "files", "database", "db",
    # version-y
    "version", "release", "build", "update",
    # too generic in a chat context
    "windows", "linux", "mac", "ios", "android",  # platforms — track separately
    "java", "python", "ruby", "node",             # languages — track separately
    # numerals / units
    "ii", "iii", "iv", "vi", "vii", "viii", "ix",
    # tokens that turned out to dominate false positives in v1
    "http", "https", "html", "url", "uri", "api", "ftp", "smtp", "ssh",
    "password", "passwords", "login", "logins", "user", "users",
    "local", "remote", "home", "personal", "public", "private",
    "admin", "root", "guest", "default",
    "united", "global", "international", "national", "world",
    "open", "smart", "easy", "fast", "free",
    "video", "audio", "image", "photo", "music", "voice",
    "secure", "security", "safe",
    "live", "active", "real", "main", "good", "best", "new", "old",
    "quick", "simple", "advanced", "premium",
    "site", "page", "link", "view", "list", "form", "menu",
    "test", "demo", "sample", "example",
    "agent", "client", "host", "node", "device", "machine",
    "auto", "manual", "custom", "default",
    "studio", "design", "draw", "paint",
    "store", "shop", "cart", "buy", "sell",
    "search", "find", "scan", "scanner",
    "share", "save", "load", "open", "close",
    "android", "iphone", "ipad", "watch",
})

# Vendor names that, when emitted as a single-token variant, generate massive
# false positives because they identify the company, not a specific product.
# These are detected dynamically from the installs data: any token that
# appears as a normalized vendor name is added to this set.
VENDOR_NAME_TOKENS: set[str] = set()

MIN_VARIANT_LEN = 4  # absolute floor; variants shorter than this are dropped


def normalize(text: str) -> str:
    """Casefold + NFKD + strip punctuation -> single-spaced lowercase string."""
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKD", text)
    text = text.casefold()
    # keep latin letters, digits, and whitespace; everything else -> space.
    # cyrillic stays as space (we are not matching cyrillic at level 1, by design)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def generate_variants(vendor: str, product: str) -> set[str]:
    """Generate matchable surface forms for a (vendor, product) pair."""
    variants: set[str] = set()

    v = normalize(vendor)
    p = normalize(product)

    if not p:
        return variants

    # 1) full normalized "vendor product" — only meaningful if vendor adds info
    if v and v not in p and len(f"{v} {p}") >= MIN_VARIANT_LEN:
        variants.add(f"{v} {p}")

    # 2) full product (always — it's the most specific form available)
    if len(p) >= MIN_VARIANT_LEN:
        variants.add(p)

    # 3) attached form (cobalt strike <-> cobaltstrike)
    p_attached = p.replace(" ", "")
    if len(p_attached) >= MIN_VARIANT_LEN and p_attached != p:
        variants.add(p_attached)

    # 4) significant tokens from product (single-word identifiers like
    #    "confluence", "esxi"). Three guards against false positives:
    #    a) only emit if exactly ONE significant token remains after filtering
    #    b) that token must NOT be a vendor name (vendor-as-token is the
    #       biggest source of FPs — see Cisco/Microsoft/Oracle in v1 results)
    #    c) the token must be >= MIN_VARIANT_LEN
    p_tokens = p.split()
    significant = [
        t for t in p_tokens
        if t not in STOPWORD_TOKENS
        and t not in VENDOR_NAME_TOKENS
        and len(t) >= MIN_VARIANT_LEN
    ]
    if len(significant) == 1:
        variants.add(significant[0])

    # final filter: drop anything too short, in stoplist, or a vendor name alone
    return {
        x for x in variants
        if len(x) >= MIN_VARIANT_LEN
        and x not in STOPWORD_TOKENS
        and x not in VENDOR_NAME_TOKENS
    }


# ---------------------------------------------------------------------------
# Lexicon build
# ---------------------------------------------------------------------------

def build_lexicon(installs_csv: Path) -> tuple[ahocorasick.Automaton, dict[str, list[tuple[str, str]]]]:
    """
    Returns:
      automaton:   pyahocorasick automaton keyed on variant strings
      variant_map: variant -> list of (vendor, product) it can refer to
                   (a single variant can map to multiple products — e.g.
                   "exchange" -> Microsoft Exchange Server, Exchange Online)
    """
    df = pd.read_csv(installs_csv)
    # dedup keeping MAX enterprises (matches Dmytro's pipeline-wide convention)
    if "enterprises" in df.columns:
        df = (
            df.sort_values("enterprises", ascending=False)
              .drop_duplicates(subset=["VendorName", "Product"], keep="first")
        )
    else:
        df = df.drop_duplicates(subset=["VendorName", "Product"], keep="first")

    # Populate VENDOR_NAME_TOKENS from the data itself: every token that
    # appears as a vendor name (single-word OR as a token of a multi-word
    # vendor name) becomes ineligible for emission as a single-token variant.
    # This kills the "cisco" -> matches all Cisco products with same count
    # pathology observed in v1 results.
    #
    # EXCEPT: don't blacklist tokens that ALSO appear as product names
    # (e.g. AnyDesk, ZoomInfo are both vendor and product) — these are
    # legitimate single-token product identifiers.
    product_tokens: set[str] = set()
    for product in df["Product"].dropna().unique():
        p_norm = normalize(product)
        if p_norm and " " not in p_norm and len(p_norm) >= MIN_VARIANT_LEN:
            product_tokens.add(p_norm)

    for vendor in df["VendorName"].dropna().unique():
        v_norm = normalize(vendor)
        if not v_norm:
            continue
        for tok in v_norm.split():
            if len(tok) >= MIN_VARIANT_LEN and tok not in product_tokens:
                VENDOR_NAME_TOKENS.add(tok)
    print(
        f"Identified {len(VENDOR_NAME_TOKENS):,} vendor-name tokens "
        f"to exclude from single-token variants",
        file=sys.stderr,
    )

    variant_map: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for vendor, product in tqdm(
        zip(df["VendorName"].fillna(""), df["Product"].fillna("")),
        total=len(df),
        desc="Generating variants",
    ):
        for variant in generate_variants(vendor, product):
            variant_map[variant].append((vendor, product))

    automaton = ahocorasick.Automaton()
    for variant in variant_map:
        automaton.add_word(variant, variant)
    automaton.make_automaton()

    # diagnostics: variants that map to many products are FP risk
    collision_prone = sorted(
        ((v, len(prods)) for v, prods in variant_map.items() if len(prods) >= 5),
        key=lambda x: -x[1],
    )
    if collision_prone:
        print(
            f"\nTop collision-prone variants (matches >=5 products — review for FPs):",
            file=sys.stderr,
        )
        for v, n in collision_prone[:15]:
            print(f"  {n:4d} products  <-  '{v}'", file=sys.stderr)
        print("", file=sys.stderr)

    print(
        f"Built lexicon: {len(df):,} unique products -> "
        f"{len(variant_map):,} surface variants",
        file=sys.stderr,
    )
    return automaton, dict(variant_map)


# ---------------------------------------------------------------------------
# Message iteration
# ---------------------------------------------------------------------------

BODY_FIELDS = ("message", "body", "text", "content")
ID_FIELDS = ("id", "message_id", "_id", "chat_id")


def _extract(obj: dict, default_id):
    body = next((obj[f] for f in BODY_FIELDS if f in obj and obj[f]), "")
    # Black Basta: chat_id is the room, not the message — combine with
    # timestamp to get a unique per-message id
    if "chat_id" in obj and "timestamp" in obj:
        msg_id = f"{obj['chat_id']}@{obj['timestamp']}"
    else:
        msg_id = next((obj[f] for f in ID_FIELDS if f in obj), default_id)
    return str(msg_id), body


def _parse_blackbasta_pseudo_json(raw: str):
    """
    Parse the Black Basta chat dump format, which looks like JSON but isn't:

        {
            timestamp: 2023-09-18 13:35:07,
            chat_id: !VdvDXHF...:matrix.bestflowers247.online,
            sender_alias: @user:matrix...,
            message: BAZA
        }
        {
            timestamp: ...
            ...
        }

    Rules we rely on:
      - Records are delimited by lines that are exactly '{' and '}'
      - Fields are 'key: value' with 4-space indent
      - 'message' can span multiple lines (everything until the closing '}'
        of the current record, minus any 'key: ' continuations)
      - There is no escaping; we treat values as raw strings
    """
    records = []
    current: dict | None = None
    current_key: str | None = None  # for multi-line message continuation

    # known top-level keys at column 4 — anything else at that indent inside a
    # record is treated as a continuation of the previous value
    known_keys = {"timestamp", "chat_id", "sender_alias", "message"}

    for line in raw.splitlines():
        stripped = line.strip()
        if stripped == "{":
            current = {}
            current_key = None
            continue
        if stripped == "}":
            if current is not None:
                records.append(current)
            current = None
            current_key = None
            continue
        if current is None:
            continue

        # try to detect "key: value" form
        # use the first ': ' OR ':' at start, but only if the prefix is a known key
        m = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*$", line)
        if m and m.group(2) in known_keys:
            key = m.group(2)
            value = m.group(3).rstrip(",")
            current[key] = value
            current_key = key
        else:
            # continuation of the previous field (typically multi-line message)
            if current_key is not None:
                current[current_key] = (current[current_key] + "\n" + stripped).strip().rstrip(",")

    return records


def iter_messages(chats_json: Path):
    """
    Yield (msg_id, body) tuples from the chat leak file.

    Tolerates four on-disk shapes, in order:
      1. Standard JSON: top-level list or dict of dicts
      2. NDJSON / JSON Lines: one object per line
      3. Concatenated JSON values (no top-level wrapper)
      4. Black Basta pseudo-JSON (unquoted keys/values, '{'...'}' records)
    """
    print(f"Loading {chats_json} ...", file=sys.stderr)
    raw = chats_json.read_text(encoding="utf-8")

    # --- attempt 1: standard JSON ------------------------------------------
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            items = data.items()
        elif isinstance(data, list):
            items = enumerate(data)
        else:
            raise ValueError(f"Unexpected top-level JSON type: {type(data).__name__}")
        for default_id, obj in items:
            if isinstance(obj, dict):
                yield _extract(obj, default_id)
        return
    except json.JSONDecodeError as e:
        print(f"  standard JSON parse failed ({e.msg} at char {e.pos}); "
              f"trying NDJSON ...", file=sys.stderr)

    # --- attempt 2: NDJSON (one object per line) ---------------------------
    ndjson_ok = True
    parsed = []
    for lineno, line in enumerate(raw.splitlines()):
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]", "{", "}"):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                parsed.append((lineno, obj))
        except json.JSONDecodeError:
            ndjson_ok = False
            break
    if ndjson_ok and parsed:
        print(f"  parsed as NDJSON: {len(parsed):,} objects", file=sys.stderr)
        for lineno, obj in parsed:
            yield _extract(obj, lineno)
        return
    print("  NDJSON parse failed; trying raw_decode stream ...", file=sys.stderr)

    # --- attempt 3: concatenated JSON values via raw_decode ----------------
    decoder = json.JSONDecoder()
    idx = 0
    n = len(raw)
    counter = 0
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
            counter += 1
        idx = end
    if raw_decode_ok and raw_decode_results:
        print(f"  parsed as concatenated JSON: {len(raw_decode_results):,} objects",
              file=sys.stderr)
        for i, obj in enumerate(raw_decode_results):
            yield _extract(obj, i)
        return
    print("  raw_decode failed; trying Black Basta pseudo-JSON ...",
          file=sys.stderr)

    # --- attempt 4: Black Basta pseudo-JSON --------------------------------
    records = _parse_blackbasta_pseudo_json(raw)
    if not records:
        raise RuntimeError(
            "Could not parse the chat file with any known strategy. "
            "Please check the file format."
        )
    print(f"  parsed as Black Basta pseudo-JSON: {len(records):,} records",
          file=sys.stderr)
    for i, obj in enumerate(records):
        yield _extract(obj, i)


# ---------------------------------------------------------------------------
# Word-boundary post-filter
# ---------------------------------------------------------------------------

def is_word_boundary(text: str, start: int, end: int) -> bool:
    """True if the span [start:end] has non-alphanumeric chars (or string edge)
    on both sides — kills substring noise like 'vm' inside 'vmstorage'."""
    left_ok = start == 0 or not text[start - 1].isalnum()
    right_ok = end == len(text) or not text[end].isalnum()
    return left_ok and right_ok


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan(
    automaton: ahocorasick.Automaton,
    variant_map: dict[str, list[tuple[str, str]]],
    chats_json: Path,
) -> pd.DataFrame:
    # (vendor, product) -> {"count": int, "msg_ids": set, "variants_hit": set}
    hits: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"count": 0, "msg_ids": set(), "variants_hit": set()}
    )

    n_msgs = 0
    n_msgs_with_hit = 0
    for msg_id, body in tqdm(iter_messages(chats_json), desc="Scanning messages"):
        n_msgs += 1
        norm = normalize(body)
        if not norm:
            continue

        msg_had_hit = False
        seen_in_msg: set[tuple[str, str]] = set()

        for end_idx, variant in automaton.iter(norm):
            start_idx = end_idx - len(variant) + 1
            if not is_word_boundary(norm, start_idx, end_idx + 1):
                continue
            for vp in variant_map[variant]:
                if vp in seen_in_msg:
                    # don't double-count same product hit twice in one message
                    # via two different variants
                    continue
                seen_in_msg.add(vp)
                rec = hits[vp]
                rec["count"] += 1
                rec["msg_ids"].add(msg_id)
                rec["variants_hit"].add(variant)
                msg_had_hit = True

        if msg_had_hit:
            n_msgs_with_hit += 1

    print(
        f"\nScanned {n_msgs:,} messages, "
        f"{n_msgs_with_hit:,} ({n_msgs_with_hit/max(n_msgs,1):.1%}) had at least one hit.",
        file=sys.stderr,
    )

    rows = [
        {
            "vendor": v,
            "product": p,
            "count": rec["count"],
            "n_unique_msgs": len(rec["msg_ids"]),
            "variants_hit": "|".join(sorted(rec["variants_hit"])),
            "msg_ids": "|".join(sorted(rec["msg_ids"])),
        }
        for (v, p), rec in hits.items()
    ]
    df = pd.DataFrame(rows).sort_values(
        ["n_unique_msgs", "count"], ascending=False
    )
    return df


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--installs",
        default="swdb_universe_installs.csv",
        help="Path to swdb_universe_installs.csv",
    )
    ap.add_argument(
        "--chats",
        default="blackbasta_chats.json",
        help="Path to blackbasta_chats.json",
    )
    ap.add_argument(
        "--out",
        default="blackbasta_product_hits.csv",
        help="Output CSV: one row per (vendor, product)",
    )
    args = ap.parse_args()

    automaton, variant_map = build_lexicon(Path(args.installs))
    result = scan(automaton, variant_map, Path(args.chats))

    out = Path(args.out)
    result.to_csv(out, index=False)
    print(
        f"\nWrote {len(result):,} rows -> {out}",
        file=sys.stderr,
    )
    # quick sanity preview
    print("\nTop 20 products by unique-message hits:", file=sys.stderr)
    print(
        result.head(20)[["vendor", "product", "count", "n_unique_msgs"]]
              .to_string(index=False),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()