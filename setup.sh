#!/bin/bash

# Check if python3-venv is installed
if ! dpkg -l | grep -q python3-venv; then
    echo "Installing python3-venv..."
    apt-get update
    apt-get install -y python3-venv python3-pip
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
echo "Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Make the main script executable
chmod +x wg-cli.py

echo "Setup complete!"
echo "To use the WireGuard CLI tool:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run the tool: ./wg-cli.py [command]" 