# Horizontal domains Recon

whois.arin.net or whoxy : Find IP block and ASN 
	Search for name only
	Collect IP block and ASN number
https://mxtoolbox.com: Find CIDR
	Check option for ASN number
	Given ASN number and find all CIDR 
https://www.ipaddressguide.com:  find all IPS or  (cidr2ip python tool)
	CIDR to IP blocks : python ../../../tools/cidr2ip.py cidr all_ip or mapcidr -cidr filename
	This is just the starting IP with the netmask, no information is added
https://viewdns.info : (horizontal domain listing)
	ASN lookup: Find asn details and get email information
	Reverse whois lookup: Using email address find the other domain owned by same email/company
https://www.lopseg.com.br/osint : all in one
	Reverse domain lookup
https://crt.sh/?q=<name>
     - %.facebook.com
https://searchdns.netcraft.com 
https://chaos.projectdiscovery.io : public program to get subdomain


Chatgpt for asking acquisition to make horizontal domain for the same company

# Vertical subdomain Recon
## Passive subdomain enumeration
(passive)

- `assetfinder wellsfargo.com | sort | uniq | tee subdomain_assetfinder.txt`
- `subfinder  -d wellsfargo.coms |sort |  uniq | tee subdomain_subfinder.txt` (set api key)
- `wfuzz -u nahamstore.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.nahamstore.thm" -c -t 100 --hc 404  ~~--hw 65~~` # subdomain from seclist
- `chaos -d wellsfargo.com -o subdomain_chaos`
- This list all the URLs and not there for subdomains
  - `gau --threads 5 wellsfargo.com |sort | uniq | tee subdomainres_gau.txt`
  - `cat subdomainres_gau.txt | awk -F '//' '{print $2}' | awk -F '/' '{print $1}' | anew subdomain_gau.txt`

### Sublist3r
Enumeration of subdomain using fuzzing
	Ffuf
	Worklist form subdomain wordlist seclist, nokov subdomain, awesome subdomain enumeration
`sublist3r -d signalpath.com | tee subdomain_sublist3r.txt`

- `sublist3r ...` (have installed but giving the problems due to some escape character)

### WAYBACK urls
`grep -v '!' SCOPE | sed 's/\*.//' | waybackurls | anew subdomain_wayback`
or iterate through all the subdomains from live_subdomain
`waybackurls  https://alternativa.film  | grep -vE ".png$|.webp$|.svg$|.jpg$|.woff$|.css"  > wayback_links `

#### Gobuster
Used for subdomain bruteforce enumeration
`gobuster dns --no-color -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -d khealth.com -o subdomaingobuster_khealth`

### Other ways to find subdomain

- Amass (active)
- Sublist3r (passive)
- Hakrawler (active crawler)
Shuffledns ( a fork of massdns) (router crashing so VPS is required
Make use of bigword list in VPS on assetnote but not locally
		shuffledns  -d wellsfargo.com -w ~/Downloads/bitquark-subdomains-top100000.txt -r  ~/Documents/probe/tools/massdns/lists/resolvers.txt -v -o subdomain_shuffledns -mode bruteforce
        
### Amass

- `amass enum -active -d wellsfargo.com -p 80,443,8080  | tee subdomain_amass.txt`
- `amass enum -brute -passive -d wellsfargo.com | tee -a susubdomain_amass_p.txt`  # brutefoce passive enumeration
- `amass viz -d3 -d <domain-name>`
- `amass track -d <domain-name>` # to track the recently added subdomain, good to hunt for recently added subdomain
- `ammas enum -df <file-with-domains> | tee subdomain_amass.txt`
- https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md
- `cat amass_res/subdomain_amass.txt  | grep -Ei  "a_record|cname_record" | awk -F ' ' '{print $1}' | anew subdomain_amass.txt`
- Update the configuration file for this
  - Config.yml
  - Datasources.yml [ check if configuration are getting loaded while running amass]
 

### Enumeration of subdomain using fuzzing

- Ffuf
- Worklist form subdomain wordlist seclist, nokov subdomain, awesome subdomain enumeration
`ffuf -v -t 400 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mode pitchfork -u http://FUZZ.zomato.com -o subdomain_fuzz`
`ffuf -w /usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt -u https://FUZZ.zomato.com -mc 200,301,302,403 -o subdomain_fuzz`

### Find Sub-subdomain
	
* Gives live subdomain and sub subdomain
- Oneforall
- `vi ~/.config/containers/registries.conf`
- `unqualified-search-registries = ["docker.io"]`
- `docker pull shmilylty/oneforall`
- `mkdir one4all_res; docker run -it --rm -v ./one4all_res:/OneForAll/results oneforall --target wellsfargo.com run` # 
<what are the other ways>


### Shuffledns ( a fork of massdns)

- `shuffledns  -d wellsfargo.com -w ~/Downloads/bitquark-subdomains-top100000.txt -r  ~/Documents/probe/tools/massdns/lists/resolvers.txt -v -o subdomain_shuffledns -mode bruteforce`
<currently not working why???>


### nslookup



### Combine all the subdomain

- `cat subdomain_* | anew all_subdomain.txt`
  
### Inscope URL
#### Installation
`git clone https://github.com/nil0x42/inscope`
`sudo cp inscope/inscope /usr/local/bin/`

#### Usage
There is `./SCOPE` file which keeps track of scope
`cat all_subdomain.txt |  inscope | tee  all_subdomain2.txt`
`mv all_subdomain2.txt all_subdomain.txt`


### (Active IP lookup/resolution from IP)
Active DNS resolution lookup tool
- `massdns -r  ../resolvers.txt -t A -o S -w live_subdomain_massdns.txt all_subdomain.txt`
- Collect the IPs from here and later do `masscan` or `nmap`
  



### Permutation 
* altdns
`cat words.txt`  # contains api,test,admin,dev,staging,qa etc
`altdns -i subdomains.txt -o perm_subdomain_tmp -w words.txt -r -s perm_subdomain -t 3 ` # permutation from words and temp is saved and then dns is resolved and saved to -s perm_subdomain_tmp
`cat perm_subdomain_tmp | cut -d '.' -f 1-3 | anew perm_subdomain_final` # extract 1 to 3 section delimited by `.` with 3 level in subdomain only
`cat perm_subdomain_final | httpx-toolkit -sc --title | anew subdomain_perm`

`cat subdomain_perm | cut -d '/' -f 3 | tr '\n' ' ' ` # convert newline to space from file

* dnsgen
  `cat domains.txt | dnsgen -w words.txt - | massdns -r /path/to/resolvers.txt -t A -o J --flush 2>/dev/null`



### Other ways to check live subdomain

- Httpx-toolkit
- `httpx-toolkit -l all_subdomain.txt -t 100  -o live_ip_subdomain_httpx_toolkit -nc -v -stats -timeout 60 -pa -fr -sc -td`
 Showing real-time statistics (-stats). The tool follows HTTP redirects (-fr), fetches HTTP status codes (-sc), and displays page titles (-td) to identify active subdomains and provide insights into the services they host, with a 60-second timeout for each request (-timeout 60). The -pa option ensures that all subdomains are probed, regardless of protocol
- Slow query to check `cat all_subdomain.txt| httprobe --prefer-https | anew live_subdomain_httprobe`
- can be given CIDR
  
### 
Go to pentesting of eyewitness section