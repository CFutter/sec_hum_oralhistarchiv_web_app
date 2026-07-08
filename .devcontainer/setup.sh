#!/bin/bash
set -e

echo "🚀 Starting OOM-safe setup..."

# Remove the broken yarn list
sudo rm -f /etc/apt/sources.list.d/yarn.list

# Update and install tools one by one to save RAM
sudo apt-get update
sudo apt-get install -y postgresql-client
sudo apt-get install -y curl
sudo apt-get clean # Clear the cache to free up memory

# Install uv
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env
fi

# Set up Python
export PATH="$HOME/.local/bin:$PATH"
uv venv
source .venv/bin/activate
uv pip install -e .

echo "✅ Setup finished successfully!"