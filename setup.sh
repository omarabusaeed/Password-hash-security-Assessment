#!/bin/bash

# Password Security Lab Setup Script
# Target: Debian/Kali Linux

echo "🔐 Initializing Password Security Lab Setup..."

# Update and install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip john hashcat docker.io docker-compose

# Install Python requirements
pip3 install -r requirements.txt

# Create necessary directories
mkdir -p data/generated_hashes data/wordlists reports modules dashboard

# Download RockYou wordlist if missing
if [ ! -f "data/wordlists/rockyou.txt" ]; then
    echo "📥 Downloading RockYou wordlist..."
    wget -O data/wordlists/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz
    gunzip data/wordlists/rockyou.txt.gz
fi

echo "✅ Setup complete. Run the dashboard with: streamlit run dashboard/app.py"
