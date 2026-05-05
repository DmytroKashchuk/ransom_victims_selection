"""
word_frequency.py

Analisi bottom-up delle parole piu frequenti nei leak di Conti e Black Basta.
Nessuna keyword preselezionata. Conta TUTTE le parole e mostra cosa emerge.

Uso:
    python3 word_frequency.py

Prerequisiti:
    - cartella conti-leaks-englished/
    - cartella BlackBasta-Chats/
    nella stessa directory dello script
"""

import json
import glob
import re
import csv
import os
from collections import Counter

# ============================================================
# STOPWORDS - parole comuni inglesi + rumore tecnico
# ============================================================
STOPWORDS = set([
    # inglese comune
    "the", "and", "that", "this", "with", "you", "for", "are", "but", "not",
    "have", "was", "all", "from", "they", "will", "can", "our", "would", "your",
    "there", "been", "more", "has", "had", "one", "out", "also", "about", "which",
    "their", "what", "into", "when", "some", "than", "other", "its", "who", "how",
    "most", "could", "these", "after", "only", "very", "them", "where", "much",
    "well", "just", "over", "such", "back", "even", "know", "any", "new", "get",
    "got", "use", "need", "make", "like", "good", "want", "let", "don", "going",
    "did", "say", "said", "does", "take", "look", "way", "still", "think", "here",
    "come", "keep", "made", "right", "should", "too", "work", "then", "were",
    "being", "each", "those", "why", "must", "things", "left", "before", "same",
    "between", "through", "down", "every", "give", "told", "yes", "sir", "now",
    "already", "many", "see", "him", "his", "her", "she", "try",
    # chat noise
    "okay", "hello", "yeah", "bro", "please", "plz", "thank", "thanks",
    "sorry", "sure", "lol", "haha", "hmm", "aha", "ooh",
    # tecnico generico
    "http", "https", "com", "www", "org", "net", "html", "php", "jpg", "png",
    "gif", "pdf", "doc", "txt", "xml", "css", "onion", "matrix", "online",
    "local", "file", "server", "localhost", "admin", "root", "user",
    "null", "true", "false", "none", "type", "content", "data", "name",
    "value", "status", "client", "message",
])


# ============================================================
# FUNZIONE: carica messaggi Conti
# ============================================================
def load_conti(base_path):
    messages = []
    pattern = base_path + "/english_chats/deepl_translated_jabber/**/*.json"
    files = sorted(glob.glob(pattern, recursive=True))
    print(f"  Trovati {len(files)} file JSON")

    for filepath in files:
        buffer = ""
        for line in open(filepath, encoding="utf-8", errors="replace"):
            buffer += line
            if line.strip() == "}":
                try:
                    obj = json.loads(buffer)
                    body = obj.get("body", "") or ""
                    sender = obj.get("from", "").split("@")[0]
                    timestamp = obj.get("ts", "")[:10]
                    messages.append({
                        "body": body,
                        "sender": sender,
                        "date": timestamp,
                        "source": "conti"
                    })
                except json.JSONDecodeError:
                    pass
                buffer = ""

    return messages


# ============================================================
# FUNZIONE: carica messaggi Black Basta
# ============================================================
def load_blackbasta(base_path):
    messages = []
    filepath = base_path + "/blackbasta_chats.json"

    with open(filepath, encoding="utf-8", errors="replace") as f:
        raw = f.read()

    blocks = raw.strip().split("\n}\n")
    for block in blocks:
        block = block.strip().strip("{").strip("}").strip()
        msg = {}
        for line in block.split("\n"):
            line = line.strip().rstrip(",")
            if ":" in line:
                key = line.split(":")[0].strip()
                val = ":".join(line.split(":")[1:]).strip()
                msg[key] = val

        if msg:
            body = msg.get("message", "")
            sender = msg.get("sender_alias", "").split(":")[0].replace("@", "")
            timestamp = msg.get("timestamp", "")[:10]
            messages.append({
                "body": body,
                "sender": sender,
                "date": timestamp,
                "source": "blackbasta"
            })

    return messages


# ============================================================
# FUNZIONE: conta parole (unigrams)
# ============================================================
def count_words(messages):
    counter = Counter()
    for msg in messages:
        body = msg["body"].lower()
        tokens = re.findall(r"\b[a-z][a-z0-9_]{2,}\b", body)
        for token in tokens:
            if token not in STOPWORDS:
                counter[token] += 1
    return counter


# ============================================================
# FUNZIONE: conta coppie di parole (bigrams)
# ============================================================
def count_bigrams(messages):
    counter = Counter()
    for msg in messages:
        body = msg["body"].lower()
        tokens = re.findall(r"\b[a-z][a-z0-9_]{2,}\b", body)
        clean = [t for t in tokens if t not in STOPWORDS]
        for i in range(len(clean) - 1):
            bigram = clean[i] + " " + clean[i + 1]
            counter[bigram] += 1
    return counter


# ============================================================
# FUNZIONE: conta parole con maiuscola (nomi di prodotto/brand)
# ============================================================
def count_capitalized(messages):
    counter = Counter()

    # parole comuni che iniziano con maiuscola ma non sono brand
    skip = set([
        "The", "This", "That", "What", "How", "Can", "Will", "But", "Not",
        "You", "They", "Are", "Was", "Has", "Had", "His", "Her", "Our", "All",
        "One", "Two", "Its", "Who", "May", "Now", "Did", "Get", "Got", "Let",
        "Yes", "New", "See", "Way", "Set", "Run", "Use", "Try", "Put", "Add",
        "End", "Big", "Old", "Own", "Few", "Ask", "Say", "And", "For", "But",
        "From", "With", "Have", "Been", "Were", "Than", "Also", "Just", "Here",
        "There", "Then", "When", "Some", "Each", "Only", "After", "Would",
        "Could", "Should", "About", "These", "Those", "Every", "Where", "Which",
        "Being", "Their", "Other", "Because", "Through", "Before", "Between",
        "Does", "Make", "Take", "Give", "Tell", "Show", "Find", "Know", "Think",
        "Come", "Work", "Look", "Want", "Need", "Keep", "Call", "Help", "Start",
        "Hello", "Good", "Well", "Sure", "Okay", "Right", "Sorry", "Thanks",
        "Please", "Maybe", "Still", "Already", "Really", "Actually", "Something",
        "Nothing", "Everything", "Everyone", "Someone", "Another", "Without",
        "General", "Report", "Money", "Price", "File", "Files", "Domain",
        "Server", "System", "Network", "Internet", "Program", "Project",
        "Version", "Access", "Account", "Service", "Process", "Command",
        "Script", "Error", "Issue", "Problem", "Question", "Answer", "Result",
        "Number", "Change", "Group", "Team", "Part", "Time", "Day", "Week",
        "Month", "Year", "Today", "Tomorrow", "Yesterday", "Morning", "Night",
        "First", "Second", "Last", "Next", "Main", "Full", "Total", "Real",
        "Local", "Global", "Public", "Private", "Free", "Paid", "Ready", "Done",
        "Sent", "Received", "Found", "NONE", "NULL", "TRUE", "FALSE",
        "INFO", "WARNING", "ERROR", "DEBUG", "FAILED", "SUCCESS",
    ])

    for msg in messages:
        body = msg["body"]
        tokens = re.findall(r"\b[A-Z][a-zA-Z0-9]{2,}\b", body)
        for token in tokens:
            if token not in skip:
                counter[token] += 1

    return counter


# ============================================================
# FUNZIONE: salva risultati in CSV
# ============================================================
def save_csv(counter, filename, header_name="word"):
    os.makedirs("output", exist_ok=True)
    filepath = "output/" + filename
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([header_name, "count"])
        for word, count in counter.most_common():
            writer.writerow([word, count])
    print(f"  Salvato: {filepath} ({len(counter)} righe)")


# ============================================================
# FUNZIONE: stampa top N
# ============================================================
def print_top(counter, n, title):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    rank = 0
    for word, count in counter.most_common(n * 2):
        if len(word) >= 3:
            rank += 1
            print(f"  {rank:>4d}. {word:<35s} {count:>7d}")
        if rank >= n:
            break


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":

    # --- CONTI ---
    print("=" * 60)
    print("CARICAMENTO CONTI")
    print("=" * 60)
    conti_msgs = []
    if os.path.exists("conti-leaks-englished"):
        conti_msgs = load_conti("conti-leaks-englished")
        print(f"  Caricati {len(conti_msgs)} messaggi")
    else:
        print("  ATTENZIONE: cartella conti-leaks-englished/ non trovata")

    # --- BLACK BASTA ---
    print()
    print("=" * 60)
    print("CARICAMENTO BLACK BASTA")
    print("=" * 60)
    bb_msgs = []
    if os.path.exists("BlackBasta-Chats"):
        bb_msgs = load_blackbasta("BlackBasta-Chats")
        print(f"  Caricati {len(bb_msgs)} messaggi")
    else:
        print("  ATTENZIONE: cartella BlackBasta-Chats/ non trovata")

    # --- CONTEGGIO PAROLE ---
    print()
    print("Conteggio parole in corso...")

    if conti_msgs:
        conti_words = count_words(conti_msgs)
        conti_bigrams = count_bigrams(conti_msgs)
        conti_caps = count_capitalized(conti_msgs)

        print_top(conti_words, 150, "TOP 150 PAROLE - CONTI")
        print_top(conti_bigrams, 80, "TOP 80 BIGRAMS - CONTI")
        print_top(conti_caps, 80, "TOP 80 NOMI/BRAND - CONTI (parole maiuscole)")

        save_csv(conti_words, "conti_word_frequency.csv")
        save_csv(conti_bigrams, "conti_bigram_frequency.csv", "bigram")
        save_csv(conti_caps, "conti_capitalized_frequency.csv")

    if bb_msgs:
        bb_words = count_words(bb_msgs)
        bb_bigrams = count_bigrams(bb_msgs)
        bb_caps = count_capitalized(bb_msgs)

        print_top(bb_words, 150, "TOP 150 PAROLE - BLACK BASTA")
        print_top(bb_bigrams, 80, "TOP 80 BIGRAMS - BLACK BASTA")
        print_top(bb_caps, 80, "TOP 80 NOMI/BRAND - BLACK BASTA (parole maiuscole)")

        save_csv(bb_words, "bb_word_frequency.csv")
        save_csv(bb_bigrams, "bb_bigram_frequency.csv", "bigram")
        save_csv(bb_caps, "bb_capitalized_frequency.csv")

    print()
    print("=" * 60)
    print("FATTO!")
    print("=" * 60)
    print()
    print("File CSV salvati in output/:")
    print("  - conti_word_frequency.csv")
    print("  - conti_bigram_frequency.csv")
    print("  - conti_capitalized_frequency.csv")
    print("  - bb_word_frequency.csv")
    print("  - bb_bigram_frequency.csv")
    print("  - bb_capitalized_frequency.csv")
    print()
    print("Questi CSV contengono TUTTE le parole ordinate per frequenza.")
    print("Da qui puoi scegliere le keyword per l'analisi in modo data-driven.")