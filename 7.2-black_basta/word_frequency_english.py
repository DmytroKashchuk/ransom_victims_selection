"""
bb_word_frequency.py

Conta la frequenza delle parole nel leak di Black Basta.
Solo parole in caratteri inglesi (a-z).

Uso:
    python3 bb_word_frequency.py

Prerequisiti:
    - cartella BlackBasta-Chats/ nella stessa directory dello script
    - clone con: git clone https://github.com/D4RK-R4BB1T/BlackBasta-Chats.git
"""

import re
import csv
import os
from collections import Counter


# parole comuni inglesi e rumore tecnico da escludere
STOPWORDS = set([
    "the", "and", "that", "this", "with", "you", "for", "are", "but", "not",
    "have", "was", "all", "from", "they", "will", "can", "our", "would", "your",
    "there", "been", "more", "has", "had", "one", "out", "also", "about", "which",
    "their", "what", "into", "when", "some", "than", "other", "its", "who", "how",
    "most", "could", "these", "after", "only", "very", "them", "where", "much",
    "well", "just", "over", "such", "back", "even", "know", "any", "new", "get",
    "got", "use", "need", "make", "like", "good", "want", "let", "don", "going",
    "did", "say", "said", "does", "take", "look", "way", "still", "think", "here",
    "come", "keep", "made", "right", "should", "too", "work", "then", "were",
    "being", "each", "those", "why", "must", "things", "give", "told", "yes",
    "now", "already", "see", "him", "his", "her", "she", "try", "okay", "hello",
    "yeah", "please", "thank", "thanks", "sorry", "sure", "lol", "hmm",
    "http", "https", "com", "www", "org", "net", "html", "php", "jpg", "png",
    "gif", "pdf", "doc", "txt", "xml", "css", "onion", "matrix", "online",
    "local", "file", "server", "localhost", "admin", "root", "user",
    "null", "true", "false", "none", "type", "content", "data", "name",
    "value", "status", "client", "message", "sent", "send", "image",
])


# carica i messaggi dal file JSON di Black Basta
def load_messages(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        raw = f.read()

    messages = []
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
        if "message" in msg:
            messages.append(msg["message"])

    return messages


# tokenizza il testo: solo parole inglesi a-z, almeno 3 caratteri
def tokenize(text):
    text = text.lower()
    tokens = re.findall(r'\b[a-z]{3,}\b', text)
    return [t for t in tokens if t not in STOPWORDS]


# conta unigrams e bigrams
def count_frequencies(messages):
    words = Counter()
    bigrams = Counter()

    for body in messages:
        tokens = tokenize(body)
        words.update(tokens)
        for i in range(len(tokens) - 1):
            bigram = tokens[i] + " " + tokens[i + 1]
            bigrams[bigram] += 1

    return words, bigrams


# salva un counter in CSV
def save_csv(counter, filepath, col_name):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([col_name, "count"])
        for item, count in counter.most_common():
            writer.writerow([item, count])


# stampa top N risultati
def print_top(counter, n, title):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    for i, (item, count) in enumerate(counter.most_common(n), 1):
        print(f"  {i:>4d}. {item:<35s} {count:>7d}")


# MAIN
if __name__ == "__main__":

    input_file = "../7-inside_groups/data/leaks/BlackBasta-Chats/blackbasta_chats.json"

    if not os.path.exists(input_file):
        print("ERRORE: file non trovato:", input_file)
        exit(1)

    print("Caricamento messaggi...")
    messages = load_messages(input_file)
    print(f"Caricati {len(messages)} messaggi")

    print("Conteggio in corso...")
    words, bigrams = count_frequencies(messages)

    print(f"Parole uniche: {len(words)}")
    print(f"Bigrams unici: {len(bigrams)}")

    # mostra top 100 parole e top 50 bigrams
    print_top(words, 100, "TOP 100 PAROLE - BLACK BASTA")
    print_top(bigrams, 50, "TOP 50 BIGRAMS - BLACK BASTA")

    # salva CSV
    os.makedirs("output", exist_ok=True)
    save_csv(words, "output/bb_words.csv", "word")
    save_csv(bigrams, "output/bb_bigrams.csv", "bigram")

    print()
    print("FATTO.")
    print("File salvati:")
    print("  output/bb_words.csv")
    print("  output/bb_bigrams.csv")