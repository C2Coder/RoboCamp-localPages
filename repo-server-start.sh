#!/bin/bash

SESSION="RepoServer"

# Kill if it already exists
screen -S "$SESSION" -X quit >/dev/null 2>&1

# Start detached session
screen -dmS "$SESSION" bash

# Run commands in separate windows
screen -S "$SESSION" -X screen -t "repo-server" bash -c "source .venv/bin/activate && python3 repo-server.py"

# Optional: set default window
screen -S "$SESSION" -p 0 -X select
