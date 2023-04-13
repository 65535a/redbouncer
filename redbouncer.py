import os
import argparse
import requests
from flask import Flask, request, redirect
import ast
import logging

requests.packages.urllib3.disable_warnings() 

instance = ""
target = ""
droptarget = ""
URI = ""
app = Flask(__name__)

event_logger = logging.getLogger('event_logger')
event_log_handler = logging.FileHandler('events.log')
event_logger.addHandler(event_log_handler)
event_logger.setLevel(logging.INFO)

blacklist = []
whitelist = []


def create_app(config=None):
    app.config.update(dict(DEBUG=False))
    app.config.update(config or {})

    required_headers = {}

    with open("headers.txt", "r") as f:
        data = f.read()
        required_headers = ast.literal_eval(data)
    with open('blacklist.txt', 'r') as bl:
        for line in bl:
            blacklist.append(line.replace("\n", ""))
    with open('whitelist.txt', 'r') as wl:
        for line in wl:
            whitelist.append(line.replace("\n", ""))

    @app.route("/"+URI, methods = ['GET', 'POST'])
    def bouncer():
        ip = request.remote_addr
        headers = dict(request.headers)
        
        if ip in blacklist:
            return redirect(droptarget)

        if ip in whitelist:
            if request.method == 'GET':
                return forward(request.method, headers, None, ip) 
            elif request.method == 'POST':
                return forward(request.method, headers, request.data.decode('UTF-8'), ip)          
        elif required_headers.items() <= headers.items():
            whitelist.append(ip)
            event_logger.info("EVENT from" + instance + ": Request from " + ip + " with correct headers. Added into whitelist.")
            if request.method == 'GET':
                return forward(request.method, headers, None, ip) 
            elif request.method == 'POST':
                return forward(request.method, headers, request.data.decode('UTF-8'), ip)
        
        blacklist.append(ip)
        event_logger.info("EVENT from" + instance + ": Request from " + ip + " with wrong headers. Added into blacklist.")
        return redirect(droptarget)

    return app


def forward(method, headers, data, og_ip):
    headers['X-Forwarded-For'] = og_ip
    if method == 'GET':
        r = requests.get(target, headers=headers, verify=False)
        return r.text
    elif method == 'POST':
        r = requests.post(target, headers=headers, data=data, verify=False)
        return r.text
    else:
        return "Bad request", 400            

if __name__ == "__main__":    
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", action="store", required=False)
    parser.add_argument("-c", "--cert", action="store", required=False)
    parser.add_argument("-k", "--key", action="store", required=False)
    parser.add_argument("-t", "--target", action="store", default="http://127.0.0.1:8000")
    parser.add_argument("-d", "--droptarget", action="store", default="https://google.com")
    parser.add_argument("-u", "--URI", action="store", default="")
    parser.add_argument("-i", "--instance", action="store", default="forwarder")

    args = parser.parse_args()
    port = int(args.port)
    cert = str(args.cert)
    key = str(args.key)
    target = str(args.target)
    droptarget = str(args.droptarget)
    URI = str(args.URI)
    instance = str(args.instance)

    app = create_app()
    if port == 443:
        app.run(host="0.0.0.0", port=port, ssl_context=(cert, key))
    else:
        app.run(host="0.0.0.0", port=port)