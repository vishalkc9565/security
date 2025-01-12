# Race condition
- Determination of 
"time-of-check to time-of-use" (TOCTOU) flaws are vulnerabilities where the value of a variable is used before it is safe to use.  A race condition vulnerability requires a 'collision' - two concurrent operations on a shared resource. So multi-threaded system would have the race condition.

Predict collision ==>> Probe ==>>> POC
[check the state where collision can occur] ==> [benchmark and then test for race condition] ==>> [if race condition is present then find the POC]
1. (limit-overrun : accessing/using values multiple times than it was suppose to be accessed)

2. Multi-endpoint race collision
- Detecting race condition
  - Predict collision attack: (race condition): check if same entity is affected. Everything is multi-step. Identify where this can impact like orders, applying code coupons, redeem codes, user and sessions
  - probe 
  - POC
  e.g. Think about the classic logic flaw in online stores where you add an item to your basket or cart, pay for it, then add more items to the cart before force-browsing to the order confirmation page. 

3. Single endpoint race condition:
  Email address confirmations, or any email-based operations, are generally a good target for single-endpoint race conditions. Emails are often sent in a background thread after the server issues the HTTP response to the client, making race conditions more likely


4. Session base locking: PHP's native session handler module only processes one request per session at a time. so send request in parallel with different session
- php has session locking sequencial execution of request so try parallel request with different session


5. Partial construction race conditions: Many applications create objects in multiple steps, which may introduce a temporary middle state in which the object is exploitable. 
- Empty array option like `param[]=` are useful when we have a lot of intermediate steps and can be intercepted for verification/confirmation if any uninitialised record is created in the intermediate steps.
- Add one more request for warming up the server

5. Time-sensitive attacks: The techniques for delivering requests with precise timing can still reveal the presence of other vulnerabilities. One such example is when high-resolution timestamps are used instead of cryptographically secure random strings to generate security tokens. 

Keywords
- Multiprocessing
- Multithreading
- Scheduling

Having inconsistent value of variable while doing the multi-process/thread
* where to find?
  - transaction step
  - coupon code
  - redeem code
  - following user
  - liking videos
  - rating

* how to find?
  - check if any endpoint have race condition which means if they have different output in sequence and inconsistent output in parallel. (User burp turbo intruder or parallel group request of repeater)
  - If there is lot of db calls for a single request in the backend then probably it has race condition

  - use `turbo-intruder` in burpsuit
      For HTTP/1, it uses the classic last-byte synchronization technique.
      For HTTP/2, it uses the single-packet attack technique, first demonstrated by PortSwigger Research at Black Hat USA 2023.
    - In burp repeater > create tab group by click `+` and then add  tabs to the group, also duplication of tab in the group is there. Try to send the packet in group in parallel and race condition is discovered. only  **HTTP/2** is preffable but not mandatory
    - check the python code to run in parallel using gate where gate is used to withold last byte of all request and at end send it for all connection.
  - use nuclei to fire parallel request
  - use curl * x times and check the final state
  
Background for TURBO Intruder:
  - Request is really fast. `Skipfish` is very fast because it does not waste time with TCP and TLS handshake. It does once and does request all.
  - `HTTP Pipelining` makes very fast, faster than `skipfish`. Browser does not support but server does . So it does the SEND, SEND, SEND and after then READ, READ, READ. It uses the same concurrent connection to send all request. so does not get limit by server number of workers running.
  - HTTP 2 does not made any much difference and hence `HTTP Pipeline`
  - `queueRequests` is the function which sends the request where requests are queued using `engine.queue` and then sent out at once using `engine.openGate` or without it
    - `concurrentConnection`: number of connection with server where the request is going to be sent for a single handshake. (1-30)
    - `requestsPerConnection`: Number of request sent per connection where if the retries increases then make the request optimal by reducing it till it reaches always 0. 10 times faster
    - `pipeline`: (boolean) make it 40 times faster
    - `learn` in `engine.queue` makes the assignment of interesting variable making it true or false. So for boring response make `learn=1` in one request and  it would become boring and `learn=1` interesting for other request which is different from this
    - `wordlists.observedWords` : all word that has be observed in the proxy
    - Inside handleResponse we can have req.engine.queue for conditional queuing on response also. Usecase example is bruteforce traversal.
   
    - `engine = engine.BURP` will use network of burp but without it, will use your local network where SSL and other burp features would not be available
    - Typically `Engine.HTTP2` is the fastest if it works followed by a well-tuned `Engine.THREADED`, followed by `Engine.BURP2` then `Engine.BURP`.
    - Can do anthing like enumerating `username/ host/ cookie/ header/file/ folder/ route` etc
  - Becuase of huge number of request, everything should not shown so we can filter out the response using `handleResponse` which we want to see so that memory does not get full.  **Before going long attacks completely different of race condition** , 
    - filter out response. 
    - stream data instead of buffering it. e.g. don't preload the wordlist but read line by lines using open `(file).readlines`
    - use wordlist
      ```
      for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())```
  - showing success resp only 
    ```
    def handleResponse(req, interesting):
      if '200 OK' in req.response:
          table.add(req)
    ```
  - Filter using decorator on table itself: https://github.com/PortSwigger/turbo-intruder/blob/master/decorators.md
  ```
  @MatchStatus(200,204)
  @MatchSizeRange(100,1000)
  def handleResponse(req, interesting):
      table.add(req)
   ``` 
```
  - For race condition, engine.start() should be after queueing it. but in other case we can start the engine and queue after it.
  - `%s` is  used for substitution
  - identification of states in the request
  - consider time to complete each request, and  figure out whether delay is due to network, backend architecture or endpoint jitters.
