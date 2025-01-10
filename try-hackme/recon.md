
### Concept
- Every penetration testing should be customised for each target category like ecommerce, banking etc
- functionality mapping
  - Ecommerce
    - Major
      * Security of Payment Gateway
      * Security of customer journey like validating form, location base vulnerability
      * Security of personal data
      * Security of integrity of catalogue
      * Security of service continuity (DoS)
      * Security of Traffic diversion

    - Minor ( based on target)
      * Search bar
      * Login
      * Oauth
      * Reset password
      * pincode ( location required)
      * request a product/replace instead of product not available/ refund if product not available
      * Add to cart
      * Favourites
      * Hosted images
      * special instruction ()
      * edit profile
      * EBT snap card
  

# Recon
- CIDR: Classless Inter Domain Routing is IP address allocation method in batch for efficience
- ASN: A collection of IP and who owns them
  - RIR: AFRINC, APNIC, ARIN, LACNIC, PIPE
- Horizontal correlation and vertical correlation

- find subdomain, IP blocks 
  - IP block + horizontal
    - arinwhois: Find IP pool ans ASN
    - mxtoolbox: CIDR using ASN
    - ipaddressguide :  to find IP range using CIDR range
    - BGP.he.net : get using ASN (this works)
    - Viewdns.info: all in one
      - reverse whois Lookup using email for horizontal correlation
      - and many more
    - lopseg.com.br/osint : all in one (IMPORTANT) ( check different options: webarchieve and check each link)
    - whoxy
    - All acquistion to collect domains using chatgpt
    - nslookup to collect dns record
    - Add API keys for the subfinder and amass to get better result



- buildwith.com 
  - to collect detailed information
- amass
  - amass intel -h
  - amass enum -active -d wellsfargo.com -p 80,443,8080  | tee subdomain_amass.txt
    ~~amass viz -d3 -d <domain-name>~~
    ~~amass track -d <domain-name> # to track the recently added subdomain, good to hunt for recently added subdomain~~
    ~~ammas enum -df <file-with-domains> | tee subdomain_amass.txt~~
    
## Shodan
shodan : a web browser for ethical hackers to browse non www part of internet whereas google does only www part of internet. ref: https://www.youtube.com/watch?v=dFH7wNyPRjM&list=PLOJR6EhNalnu7hgxu7QhA9GrF9i23JX9A&index=8
    - create account 
    - use filter like http.title, http.status
    - open URL which have wierd title or status code like 404
    - it also give new IPs for us to explore
    - its pretty easy to search as filter can be applied with <name>:<atr> and - for negative result
    - https://internetdb.shodan.io 
## hunterhow: (small network than shodan)
    https://hunter.how/


## Webarchive
ref: https://archive.org/developers/wayback-cdx-server.html
- Usage
http://web.archive.org/cdx/search/cdx?url=<domain-name>

 - check robot/admin or something from the result



### Chaos Project Discovery
https://chaos.projectdiscovery.io : get subdomain of public bounty programs

chaos client for cli

### Manually finding subdomain
    - crt.sh 
      - %.facebook.com
    - virustotal.com
    - netcraft dns
    - Project discovery io chaos

## commands to find domain
<TODO> at subdomain-enum.md


### httpx-toolkit/probe to do following 
- Check domain is live or not
- Probe attribute gives the result in Pass/Fail format 
- CIDR ping
- ASN ping
- Tech stack and status code check [very important]
- Screenshot
  `httpx-toolkit -l all_subdomain.txt -t 100  -o live_ip_subdomain_httpx_toolkit -nc -v -stats -timeout 60 -pa -fr -sc -td`
- don't give any analysis to ip just proceed with subdomain eyewitness
  - `cat live_ip_subdomain_httpx_toolkit live_subdomain_httprobe | awk -F ' ' '{print $1}'| awk -F '^http://|^https://' '{print $2}' | uniq |  anew  live_subdomain`

 

###  Eyewitness cmd for screenshot
–timeout, -F filename, –web, –thread

`eyewitness --web -f live_subdomain --timeout 100 -d livesubdomain_screenshot_eye --thread 4 --prepend-https`
- To resume the screenshot process
  `eyewitness --resume`

#### Bypass 403
- Sometimes the response code is 403 which can fetch the URL using X-Forwarded-For
`X-Forwarded-For: 127.0.0.1:80`


### Record all response 

`awk '{print "https://"$1"/"}'  live_subdomain > live_subdomain_with_http `
`meg --verbose  ~/combined_words.txt  live_subdomain_with_http  meg.out  -d 5000 -c 100`

- find resources like `roboot.txt`, `package.json` `.well-known/security.txt`

====>>>  secret information in try/hackme/readme.md

	
### Directory brute forcing
`gobuster dir -u "https://www.zerobounce.net/docs/" -w ~/Downloads/combined_words.txt -t 100 -b 429,301 -r` 
  * If error found then add `--timeout 2s`
Or `dirsearch -u <url>` # good for bruteforcing for file and subdomains
Or 
`dirb https://www.zerobounce.net <wordlist>` # does recursive directory iteration

Or ffuf



#------------------------------------------------------
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
tricks:
- parametrised URL with status code 200 has most of the vulnerability
- sub-subdomain has chance of finding more bug than subdomain
- make use of server on digital ocean or aws for faster response







what is fingerprinting of subdomain
CIA triat ???
HTML template injection
web cache poisoning


task 1: try hack : pre  security
task 2: choose a target (big company, ) and gather every domain related to target and IPs
