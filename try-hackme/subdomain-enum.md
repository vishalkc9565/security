## Horizontal domains Recon

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

## Vertical subdomain Recon
### Passive subdomain enumeration
(passive)

- `assetfinder wellsfargo.com | uniq | tee subdomain_assetfinder.txt`
- `subfinder  -d wellsfargo.com -all -silent | uniq | tee  subdomain_subfinder.txt` (set api key)
- `gau --threads 5 wellsfargo.com | tee subdomainres_gau.txt`
- `cat subdomainres_gau.txt | awk -F '//' '{print $2}' | awk -F '/' '{print $1}' | anew subdomain_gau.txt`
- `chaos -d wellsfargo.com -o subdomain_chaos`

### Sublist3r
Enumeration of subdomain using fuzzing
	Fuff 
	Worklist form subdomain wordlist seclist, nokov subdomain, awesome subdomain enumeration
 

- `sublist3r ...` (have installed but giving the problems due to some escape character)

### Other ways to find subdomain

- Amass (active)
- Sublist3r (passive)
- Hakrawler (active crawler)
Shuffledns ( a fork of massdns) (router crashing so VPS is required
Make use of bigword list in VPS on assetnote but not locally
		shuffledns  -d wellsfargo.com -w ~/Downloads/bitquark-subdomains-top100000.txt -r  ~/Documents/probe/tools/massdns/lists/resolvers.txt -v -o subdomain_shuffledns -mode bruteforce
        
### Amass

- `amass enum -active -d wellsfargo.com -p 80,443,8080  | tee subdomain_amass.txt`
- `amass viz -d3 -d <domain-name>`
- `amass track -d <domain-name>` # to track the recently added subdomain, good to hunt for recently added subdomain
- `ammas enum -df <file-with-domains> | tee subdomain_amass.txt`
- https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md
- `cat amass_res/subdomain_amass.txt  | grep -Ei  "a_record|cname_record" | awk -F ' ' '{print $1}' | anew subdomain_amass.txt`
- Update the configuration file for this
  - Config.yml
  - Datasources.yml [ check if configuration are getting loaded while running amass]
 
### Enumeration of subdomain using fuzzing

- Fuff
- Worklist form subdomain wordlist seclist, nokov subdomain, awesome subdomain enumeration

### Find Sub-subdomain

- Oneforall
- `vi ~/.config/containers/registries.conf`
- `unqualified-search-registries = ["docker.io"]`
- `docker pull shmilylty/oneforall`
- `mkdir one4all_res; docker run -it --rm -v ./one4all_res:/OneForAll/results oneforall --target wellsfargo.com run` # Gives live subdomain and sub subdomain
<what are the other ways>


### Shuffledns ( a fork of massdns)

- `shuffledns  -d wellsfargo.com -w ~/Downloads/bitquark-subdomains-top100000.txt -r  ~/Documents/probe/tools/massdns/lists/resolvers.txt -v -o subdomain_shuffledns -mode bruteforce`
<currently not working why???>
### Combine all the subdomain

- `cat subdomain_* | anew all_subdomain.txt`

### (Active IP lookup)
Active DNS resolution lookup tool
- `massdns -r  ../tools/massdns/lists/resolvers.txt -t A -o S -w live_subdomain.txt all_subdomain.txt`
- Collect the IPs from here and later do `masscan` or `nmap`
- 

### Other ways to check live subdomain

- Httpx-toolkit
- `httpx-toolkit -l all_subdomain.txt -t 100  -o live_subdomain_httpx_toolkit -nc -v -stats -timeout 60 -pa -fr -sc -td`
 Showing real-time statistics (-stats). The tool follows HTTP redirects (-fr), fetches HTTP status codes (-sc), and displays page titles (-td) to identify active subdomains and provide insights into the services they host, with a 60-second timeout for each request (-timeout 60). The -pa option ensures that all subdomains are probed, regardless of protocol
- `cat all_subdomain.txt| httprobe --prefer-https | anew live_domain_httprobe`
- can be given CIDR
  
### 
Go to pentesting of eyewitness section