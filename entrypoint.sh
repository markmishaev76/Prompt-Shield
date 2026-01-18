#!/bin/bash
set -e

echo "🛡️ Prompt Shield - GitHub Action"
echo "=================================="
echo ""

# Run the Python scanner
python /app/integrations/github_action.py
