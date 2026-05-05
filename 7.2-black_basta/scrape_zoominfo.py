"""Extract every zoominfo.com URL from the chat leak. One URL per line."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from extract_websites import iter_messages_with_meta

ZI_RE = re.compile(
    r"(?:https?://)?(?:[a-z0-9-]+\.)*zoominfo\.[a-z.]{2,8}(?:/[^\s<>\"'`,()\[\]{}]*)?",
    re.IGNORECASE,
)

def main():
    chats = sys.argv[1] if len(sys.argv) > 1 else "blackbasta_chats.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "zoominfo_urls.txt"

    urls = set()
    for rec in iter_messages_with_meta(Path(chats)):
        body = rec["message"]
        if body and "zoominfo" in body.lower():
            for m in ZI_RE.finditer(body):
                urls.add(m.group(0).rstrip(".,;:!?)"))

    Path(out).write_text("\n".join(sorted(urls)) + "\n")
    print(f"Wrote {len(urls)} URLs -> {out}")

if __name__ == "__main__":
    main()