#!/usr/bin/env python3
"""
Domain Resolver for VERIS Dataset — Anthropic Batch API version
================================================================
Resolves company domains using the Message Batches API.
- No rate limits
- 50% cheaper tokens
- Web search supported
- Processes up to 10,000 requests per batch

Usage:
    export ANTHROPIC_API_KEY="sk-ant-..."

    # Step 1: Submit batch (groups of 20 companies per request)
    python3 find_domains_batch.py submit --input veris_export.csv

    # Step 2: Check status
    python3 find_domains_batch.py status --batch-id msgbatch_XXXXX

    # Step 3: Collect results when done
    python3 find_domains_batch.py collect --batch-id msgbatch_XXXXX --output domains_resolved.csv

    # Or do it all in one go (submits, polls, collects):
    python3 find_domains_batch.py run --input veris_export.csv --output domains_resolved.csv
"""

import anthropic
import csv
import json
import os
import sys
import time
import argparse
import re
import hashlib


# ── Configuration ──────────────────────────────────────────────────────────────
COMPANIES_PER_REQUEST = 20      # Companies per API request within the batch
MODEL = "claude-sonnet-4-5-20250929"
MAX_TOKENS = 4096
POLL_INTERVAL = 30              # seconds between status checks

SYSTEM_PROMPT = """You are a domain name resolver for cybersecurity research. Given a list of company/organization names, return the precise primary domain name for each one.

Rules:
- Return ONLY the root domain (e.g., "google.com" not "www.google.com" or "https://google.com")
- For government agencies, return their .gov or official domain
- For hospitals/healthcare, return their official website domain
- For universities, return their .edu or official domain
- If the entity is too generic (e.g., "Unknown", "Gas Station", "various"), set domain to null
- If the company is defunct, return the last known domain and note "defunct" 
- If you are NOT confident, set confidence to "low"

You MUST respond with ONLY a valid JSON array. No markdown, no code fences, no explanation.
Each element: {"name": "Original Name", "domain": "example.com", "confidence": "high|medium|low", "notes": ""}
If domain is unknown, use: {"name": "Original Name", "domain": null, "confidence": "none", "notes": "reason"}"""


# ── Helper functions ───────────────────────────────────────────────────────────

def load_companies(input_path: str) -> list:
    """Extract unique company names from the VERIS CSV."""
    companies = set()
    with open(input_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get('organization', '').strip()
            if name:
                companies.add(name)
    return sorted(companies)


def make_custom_id(batch_idx: int, companies: list) -> str:
    """Create a deterministic custom_id for a batch of companies."""
    # Use hash of company names to make it deterministic and resumable
    content = "|".join(companies)
    h = hashlib.md5(content.encode()).hexdigest()[:8]
    return f"batch_{batch_idx:04d}_{h}"


def chunk_list(lst, n):
    """Split list into chunks of size n."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def parse_json_response(text: str) -> list:
    """Extract and parse JSON array from response text."""
    text = text.strip()
    # Remove markdown code fences
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    text = text.strip()

    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try to find JSON array in text
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    return []


def build_requests(companies: list, use_search: bool = False) -> list:
    """Build batch request objects from company list."""
    requests = []
    chunks = list(chunk_list(companies, COMPANIES_PER_REQUEST))

    for idx, chunk in enumerate(chunks):
        company_list = "\n".join(f"- {c}" for c in chunk)
        user_content = f"Find the precise domain name for each of these {len(chunk)} organizations:\n\n{company_list}"

        params = {
            "model": MODEL,
            "max_tokens": MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_content}],
        }

        if use_search:
            params["tools"] = [{
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": 3  # limit searches per request to control cost
            }]

        requests.append({
            "custom_id": make_custom_id(idx, chunk),
            "params": params
        })

    return requests, chunks


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_submit(args):
    """Submit a batch job."""
    client = anthropic.Anthropic()

    print(f"Loading companies from {args.input}...")
    companies = load_companies(args.input)
    print(f"  Found {len(companies)} unique companies")

    # Check for already-resolved companies to skip
    already_resolved = set()
    if args.output and os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('domain') and row.get('confidence') in ('high', 'medium'):
                    already_resolved.add(row['company_name'])
        print(f"  Already resolved (high/medium): {len(already_resolved)}")
        companies = [c for c in companies if c not in already_resolved]
        print(f"  Remaining to process: {len(companies)}")

    if not companies:
        print("Nothing to process!")
        return

    use_search = args.search
    requests, chunks = build_requests(companies, use_search=use_search)
    print(f"  Created {len(requests)} requests ({COMPANIES_PER_REQUEST} companies each)")
    print(f"  Web search: {'enabled' if use_search else 'disabled'}")

    # Save the mapping of custom_id → company names for later
    mapping = {}
    for req, chunk in zip(requests, chunks):
        mapping[req['custom_id']] = chunk

    mapping_path = args.mapping or "batch_mapping.json"
    with open(mapping_path, 'w') as f:
        json.dump(mapping, f)
    print(f"  Saved mapping to {mapping_path}")

    # Submit batch
    print(f"\nSubmitting batch to Anthropic API...")
    batch = client.messages.batches.create(requests=requests)

    print(f"\n{'='*50}")
    print(f"  Batch ID:     {batch.id}")
    print(f"  Status:       {batch.processing_status}")
    print(f"  Expires at:   {batch.expires_at}")
    print(f"  Requests:     {batch.request_counts.processing} processing")
    print(f"{'='*50}")
    print(f"\nNext steps:")
    print(f"  Check status:   python3 find_domains_batch.py status --batch-id {batch.id}")
    print(f"  Collect results: python3 find_domains_batch.py collect --batch-id {batch.id} --output domains_resolved.csv --mapping {mapping_path}")

    return batch.id


def cmd_status(args):
    """Check batch status."""
    client = anthropic.Anthropic()
    batch = client.messages.batches.retrieve(args.batch_id)

    total = (batch.request_counts.succeeded + batch.request_counts.errored +
             batch.request_counts.canceled + batch.request_counts.expired +
             batch.request_counts.processing)

    print(f"Batch: {batch.id}")
    print(f"  Status:     {batch.processing_status}")
    print(f"  Succeeded:  {batch.request_counts.succeeded}")
    print(f"  Processing: {batch.request_counts.processing}")
    print(f"  Errored:    {batch.request_counts.errored}")
    print(f"  Canceled:   {batch.request_counts.canceled}")
    print(f"  Expired:    {batch.request_counts.expired}")
    print(f"  Total:      {total}")

    if batch.processing_status == "ended":
        print(f"\n  ✅ Batch complete! Results URL: {batch.results_url}")
        print(f"  Run: python3 find_domains_batch.py collect --batch-id {batch.id} --output domains_resolved.csv")
    else:
        pct = (batch.request_counts.succeeded / total * 100) if total > 0 else 0
        print(f"\n  ⏳ Still processing... ({pct:.1f}% done)")

    return batch.processing_status


def cmd_collect(args):
    """Collect results from a completed batch."""
    client = anthropic.Anthropic()

    # Load mapping
    mapping_path = args.mapping or "batch_mapping.json"
    if os.path.exists(mapping_path):
        with open(mapping_path, 'r') as f:
            mapping = json.load(f)
        print(f"Loaded mapping from {mapping_path} ({len(mapping)} request groups)")
    else:
        mapping = {}
        print(f"Warning: No mapping file found at {mapping_path}. Company name matching may be less accurate.")

    # Check status first
    batch = client.messages.batches.retrieve(args.batch_id)
    if batch.processing_status != "ended":
        print(f"Batch is still {batch.processing_status}. Wait for it to finish.")
        return

    print(f"Downloading results for batch {args.batch_id}...")
    print(f"  Succeeded: {batch.request_counts.succeeded}")
    print(f"  Errored:   {batch.request_counts.errored}")

    # Stream results
    all_results = {}
    succeeded = 0
    failed = 0

    for result in client.messages.batches.results(args.batch_id):
        custom_id = result.custom_id

        if result.result.type == "succeeded":
            # Extract text from the message
            text_parts = []
            for block in result.result.message.content:
                if hasattr(block, 'text'):
                    text_parts.append(block.text)

            full_text = "\n".join(text_parts)
            parsed = parse_json_response(full_text)

            # Get expected company names from mapping
            expected_companies = mapping.get(custom_id, [])

            for item in parsed:
                if not isinstance(item, dict) or 'name' not in item:
                    continue

                name = item['name']
                domain = item.get('domain') or ''
                if isinstance(domain, str):
                    domain = domain.strip().lower()
                    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
                    domain = domain.rstrip('/')
                else:
                    domain = ''

                if domain in ('null', 'none', 'skip', 'n/a', ''):
                    domain = ''

                confidence = item.get('confidence', 'low')
                notes = item.get('notes', '') or ''

                # Match to original name
                matched = name
                for orig in expected_companies:
                    if orig.lower() == name.lower() or orig == name:
                        matched = orig
                        break

                all_results[matched] = {
                    'company_name': matched,
                    'domain': domain,
                    'confidence': confidence,
                    'notes': notes,
                }

            succeeded += 1

        elif result.result.type == "errored":
            error_msg = str(result.result.error) if hasattr(result.result, 'error') else 'unknown error'
            # Mark all companies in this group as errored
            for company in mapping.get(custom_id, []):
                all_results[company] = {
                    'company_name': company,
                    'domain': '',
                    'confidence': 'error',
                    'notes': f'API error: {error_msg}',
                }
            failed += 1

    # If there's an existing output, merge
    output_path = args.output or "domains_resolved.csv"
    if os.path.exists(output_path):
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row['company_name']
                # Only keep existing if new result is worse
                if name not in all_results or (
                    not all_results[name]['domain'] and row.get('domain')
                ):
                    all_results[name] = row

    # Write output
    fieldnames = ['company_name', 'domain', 'confidence', 'notes']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for name in sorted(all_results.keys()):
            writer.writerow(all_results[name])

    # Stats
    total = len(all_results)
    with_domain = sum(1 for r in all_results.values() if r['domain'])
    high = sum(1 for r in all_results.values() if r['confidence'] == 'high')
    medium = sum(1 for r in all_results.values() if r['confidence'] == 'medium')
    low = sum(1 for r in all_results.values() if r['confidence'] == 'low')
    errors = sum(1 for r in all_results.values() if r['confidence'] == 'error')

    print(f"\n{'='*50}")
    print(f"RESULTS")
    print(f"{'='*50}")
    print(f"  API requests: {succeeded} succeeded, {failed} failed")
    print(f"  Companies:    {total} total")
    print(f"  Domains found: {with_domain} ({with_domain/total*100:.1f}%)")
    print(f"    High:   {high}")
    print(f"    Medium: {medium}")
    print(f"    Low:    {low}")
    print(f"    Errors: {errors}")
    print(f"  Output: {output_path}")


def cmd_run(args):
    """Submit, poll, and collect in one go."""
    # Submit
    args_submit = argparse.Namespace(
        input=args.input,
        output=args.output,
        search=args.search,
        mapping=args.mapping,
    )
    batch_id = cmd_submit(args_submit)
    if not batch_id:
        return

    # Poll
    print(f"\nPolling for completion (every {POLL_INTERVAL}s)...")
    args_status = argparse.Namespace(batch_id=batch_id)
    while True:
        time.sleep(POLL_INTERVAL)
        status = cmd_status(args_status)
        if status == "ended":
            break
        print(f"  Waiting {POLL_INTERVAL}s...")

    # Collect
    print(f"\nCollecting results...")
    args_collect = argparse.Namespace(
        batch_id=batch_id,
        output=args.output or "domains_resolved.csv",
        mapping=args.mapping,
    )
    cmd_collect(args_collect)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Resolve company domains using Anthropic Batch API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # All-in-one (submit, wait, collect):
  python3 find_domains_batch.py run --input veris_export.csv --output domains.csv

  # With web search (more accurate, costs more):
  python3 find_domains_batch.py run --input veris_export.csv --output domains.csv --search

  # Step by step:
  python3 find_domains_batch.py submit --input veris_export.csv
  python3 find_domains_batch.py status --batch-id msgbatch_XXXXX
  python3 find_domains_batch.py collect --batch-id msgbatch_XXXXX --output domains.csv
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Submit
    p_submit = subparsers.add_parser('submit', help='Submit batch job')
    p_submit.add_argument('--input', required=True, help='Input VERIS CSV')
    p_submit.add_argument('--output', help='Existing output CSV to skip already-resolved')
    p_submit.add_argument('--search', action='store_true', help='Enable web search (more accurate, +$10/1000 searches)')
    p_submit.add_argument('--mapping', default='batch_mapping.json', help='Path to save request mapping')

    # Status
    p_status = subparsers.add_parser('status', help='Check batch status')
    p_status.add_argument('--batch-id', required=True, help='Batch ID from submit')

    # Collect
    p_collect = subparsers.add_parser('collect', help='Collect results')
    p_collect.add_argument('--batch-id', required=True, help='Batch ID')
    p_collect.add_argument('--output', default='domains_resolved.csv', help='Output CSV')
    p_collect.add_argument('--mapping', default='batch_mapping.json', help='Path to request mapping')

    # Run (all-in-one)
    p_run = subparsers.add_parser('run', help='Submit, poll, and collect (all-in-one)')
    p_run.add_argument('--input', required=True, help='Input VERIS CSV')
    p_run.add_argument('--output', default='domains_resolved.csv', help='Output CSV')
    p_run.add_argument('--search', action='store_true', help='Enable web search')
    p_run.add_argument('--mapping', default='batch_mapping.json', help='Path to save request mapping')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Check API key
    if not os.environ.get('ANTHROPIC_API_KEY'):
        print("ERROR: Set ANTHROPIC_API_KEY environment variable")
        sys.exit(1)

    if args.command == 'submit':
        cmd_submit(args)
    elif args.command == 'status':
        cmd_status(args)
    elif args.command == 'collect':
        cmd_collect(args)
    elif args.command == 'run':
        cmd_run(args)


if __name__ == '__main__':
    main()