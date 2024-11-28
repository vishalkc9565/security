## Web cache deception
This is different from web cache poisioning.
Web cache deception exploits cache rules to trick the cache into storing sensitive or private content, which the attacker can then access. 

- cache key: URL, query, cache headers, content type
- 










## Web cache poisoning
- Web cache poisoning manipulates cache keys to inject malicious content into a cached response, which is then served to other users.
- Sending harmful response to user as a result of cacheing
- A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting vulnerabilities such as XSS, JavaScript injection, open redirection, and so on. 

### Impact
    - what can be cached by attacker
    - amount of traffic hitting on cache
### STEPS TO CREATE THE ATTTACK

1. Identify and evaluate the unkey input (manual work and time-consuming: Burp: param miner > guess headers > result:output tab : free community version)
   1. Always maintain a new key for cache so that you get data from server directly
2. Elicit a harmful response fromt the back-end server (_)
3. Get response cached




