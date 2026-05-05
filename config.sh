#!/usr/bin/env bash
# Configurazione condivisa per push_data.sh e pull_data.sh
# Modifica i valori qui sotto in base al tuo server.

# Utente e host del server SSH
REMOTE_USER="dima"
REMOTE_HOST="10.20.5.21"

# Percorso assoluto della repo gia clonata sul server remoto
REMOTE_PATH="/home/dima/ransom_victims_selection"

# Percorso locale del progetto (default: cartella dove sta lo script)
LOCAL_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pattern dei file da sincronizzare (aggiungi qui altri tipi se serve)
FILE_PATTERNS=("*.csv" "*.json")

# Porta SSH (cambia se il server usa una porta non standard)
SSH_PORT=22