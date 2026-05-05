#!/usr/bin/env bash
# Sincronizza i file locali verso la repo clonata sul server remoto.
# Modalita: add/update (non cancella file sul remote).
# Preserva la struttura delle cartelle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

# Costruisco un --include per ogni pattern definito in config.sh
INCLUDES=()
for pattern in "${FILE_PATTERNS[@]}"; do
    INCLUDES+=(--include="${pattern}")
done

RSYNC_OPTS=(
    -avz                          # archive + verbose + compress
    --prune-empty-dirs            # non creare cartelle vuote sul remote
    --include='*/'                # ricorsione nelle sottocartelle
    "${INCLUDES[@]}"              # include i file che ci interessano
    --exclude='*'                 # escludi tutto il resto
    --exclude='.git/'             # safety: mai toccare .git
    -e "ssh -p ${SSH_PORT}"
)

SRC="${LOCAL_PATH}/"
DST="${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "=== PUSH: ${SRC} -> ${DST} ==="
rsync "${RSYNC_OPTS[@]}" "${SRC}" "${DST}"
echo "=== Fatto. ==="