#!/bin/bash

# # Check if a domain name is passed as an argument
# if [ "$#" -lt 1 ]; then
#     echo "Usage: $0 <domain-name>"
#     exit 1
# fi

# Check if a SCOPE file is provided
if [ ! -f "SCOPE" ]; then
    echo "SCOPE file not found. Please provide a SCOPE file with domain entries."
    exit 1
fi
 
# Timestamp for directory naming
timestamp=$(date +"%Y%m%d_%H%M%S")

# Define output directory in /tmp with timestamp
output_dir="../tmp_dir/$timestamp"
mkdir -p "$output_dir"
mv * $output_dir
mv $output_dir/SCOPE .
mv $output_dir/readme.md .


echo "Reading domains from SCOPE file and processing each domain..."
# Read and process each domain from SCOPE file
while IFS= read -r line || [[ -n "$line" ]]; do
    # Extract domain using awk
    domain=$(echo "$line" | awk -F '*' '{ print $2 }' | sed 's/^\.//' )
    
    if [ -z "$domain" ]; then
        echo "Invalid entry in SCOPE file: $line. Skipping..."
        continue
    fi

    echo "Processing domain: $domain"
  
    # 2. Run assetfinder and save unique subdomains
    echo "Running subfinder for $domain..."
    assetfinder "$domain" | uniq | anew "subdomain_assetfinder.txt"

    # 3. Run subfinder and save unique subdomains (ensure API key is set)
    echo "Running assetfinder for $domain..."
    subfinder -d "$domain" | uniq | anew "subdomain_subfinder.txt"
    echo "*************************************************"

done < "SCOPE"

cat subdomain_* | anew all_subdomain.txt 
tmp_file="all_subdomain_tmp.txt"
# 4. Filter aggregated subdomains for in-scope domains
if [ -f all_subdomain.txt ]; then
    echo "Found all_subdomain.txt. Filtering in-scope subdomains using inscope..."
    cat all_subdomain.txt | inscope | tee "$tmp_file"
    mv "$tmp_file" all_subdomain.txt
    # rm -f "$tmp_file"
else
    echo "all_subdomain.txt not found. Skipping in-scope filtering step."
fi

# 5. Run chaos to find subdomains and save the output
chaos -d "$domain" -o "subdomain_chaos.txt"

# 6. Run httpx-toolkit to check for live subdomains
if [ -f all_subdomain.txt ]; then
    echo "Found all_subdomain.txt. Running httpx-toolkit to check for live subdomains..."
    httpx-toolkit -l all_subdomain.txt -t 100 -o "live_subdomain_httpx_toolkit.txt" -nc -v -stats -timeout 60 -pa -fr -sc -td
else
    echo "all_subdomain.txt not found. Skipping httpx-toolkit step."
fi

mkdir amass_res/
while IFS= read -r line || [[ -n "$line" ]]; do
    # Extract domain using awk
    domain=$(echo "$line" | awk -F '*' '{ print $2 }' | sed 's/^\.//' )
    
    # 7. Run active enumeration and save the output
    amass enum --active -d "$domain" -p 80,443,8080 | anew "amass_res/subdomain_amass_$domain.txt"

done < "SCOPE"

echo "All commands completed. Results are saved in $output_dir"

