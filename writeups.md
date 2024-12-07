## amazing writeups
https://github.com/devanshbatham/Awesome-Bugbounty-Writeups






ref: 
- check the hacker activity everyday
- https://ars0nsecurity.com/pages/methodology
- books.hacktricks
- checkout the ars0n git repo for notes


Tools or addon:
- wappalyzer
- dom-invador (check for sources and sinks)
- js-scanner burp suite addon


## Normal Functions
- Burp > search > API keys
- Engagement tool >  find (comment|reference|scripts| target) 
  - (target): check for static urls, parameters
- Check if the js is not serialised (react) properly then read the code to get the extra edze 
- When brute-force attack is (block by IP| or other reason) then `X-Forwarded-For:127.0.0.1|[127.0.0.1, 10.9.57.57]`

# Client side Injection
## INJECTION ATTACK

- check if the request has param
- Check if we can play with param and change with parameter change in  output result (output content)
  - First GET, POST
  - have a lot of variation of the xss
  - have the server listening to check if the xss worked if pinged happended
  - setup the collaborator of the cracked
  - web cache positioning : if the cache is present then everyone is can be affected
    - check for cache response header
  - if response has `content-type` is `text/html`, then dig in to check xss
  - react handles the xss pretty well, vue and angular have problems
  - if any URL(IPs) are there in reference of burpsuits, check for csrf where I can do request to this URL if Xss if found somewhere else
  - Automatic redirect to 3rd party website is bug: e.g `/logout?redirect_url=evil.com`



# Server Side Injection
### server-side Prototype pollution ( challenging)
    - change of json request body to break the logic like adding `hasOwnProperty` 
### NoSql injection
    - this is prevalant now
    - if the request body and response body is json then it could be
      - books.hacktrick has payload for this for json as well as parameters [$ne]

### SAML
    - single single sign-on uses saml
    - read this (IMP)
    - 


## Compliance
- PII:  
- PHI: hippa voilation: nobody else can store the information
- PCI DSS ( payment card information information)

## remind to check
-  blind xss
-  client side prototype pollution
-  https request smuggle  






