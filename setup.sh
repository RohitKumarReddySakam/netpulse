#!/bin/bash
set -e
echo "=== NETPULSE Setup ==="
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
mkdir -p instance
cp .env.example .env 2>/dev/null || true
echo "Setup complete. Start with: python app.py"
