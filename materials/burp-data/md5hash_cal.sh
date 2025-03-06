while read -r line; do printf %s "$line" | md5sum | cut -f1 -d' '; done < materials/burp-data/tmp/password.txt 
while IFS= read -r line; do echo "$line" | base64 ; done < materials/burp-data/tmp/password_md5.txt 
while read -r line; do printf %s "$line" | base64 ; done < materials/burp-data/tmp/password_md5.txt 
