#!/bin/bash

# SCP script to transfer the data folder to an SSH server
# Usage: ./scp_transfer.sh <user> <host> <remote_path>
# Example: ./scp_transfer.sh myuser 192.168.1.100 /home/myuser/

if [ $# -lt 3 ]; then
    echo "Usage: $0 <user> <host> <remote_path>"
    echo "Example: $0 myuser 192.168.1.100 /home/myuser/"
    exit 1
fi

USER="$1"
HOST="$2"
REMOTE_PATH="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"

if [ ! -d "$DATA_DIR" ]; then
    echo "Error: data directory not found at $DATA_DIR"
    exit 1
fi

echo "Transferring data folder to $USER@$HOST:$REMOTE_PATH ..."
scp -r "$DATA_DIR" "$USER@$HOST:$REMOTE_PATH"

if [ $? -eq 0 ]; then
    echo "Transfer complete."
else
    echo "Transfer failed."
    exit 1
fi
