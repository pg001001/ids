#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1

# Ensure all required scripts are executable
chmod +x subdomain_find.sh url_find.sh information.sh 

# Run subdomain enumeration 
echo "Starting subdomain enumeration..."
./subdomain_find.sh "$domain"

# Run URL enumeration 
echo "Starting url enumeration..."
./url_find.sh "$domain"

# Run JavaScript file analysis 
echo "Starting JavaScript file analysis..."
./information.sh "$domain"

echo "All tasks completed for ${domain}. Results are stored in the respective directories."
