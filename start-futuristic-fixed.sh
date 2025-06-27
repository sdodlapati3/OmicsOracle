#!/bin/bash
# Start the futuristic interface with proper logging

# Set NCBI email
export NCBI_EMAIL="omicsoracle@example.com"

# Make sure entrez_patch.py exists (created earlier)
echo "Starting futuristic interface with proper NCBI configuration"
echo "NCBI_EMAIL set to: $NCBI_EMAIL"

# Start the interface with detailed logging
cd interfaces/futuristic
python main.py
