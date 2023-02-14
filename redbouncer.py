import os
import argparse
import requests
from flask import Flask, request, redirect
import ast
import threading

requests.packages.urllib3.disable_warnings() 

target = ""
droptarget = ""
URI = ""
app = Flask(__name__)

blacklistList = []
whitelistList = []

def create_app(config=None):
    app.config.update(dict(DEBUG=False))
    app.config.update(config or {})

    required_headers = {}

    with open("headers.txt", "r") as f:
        data = f.read()
        required_headers = ast.literal_eval(data)

    @app.route("/"+URI, methods = ['GET', 'POST'])
    def bouncer():
        ip = request.remote_addr
        headers = dict(request.headers)
        
        if ip in blacklistList:
            return redirect(droptarget)

        if ip in whitelistList:
            if request.method == 'GET':
                return forward(request.method, headers, None, ip) 
            elif request.method == 'POST':
                return forward(request.method, headers, request.data.decode('UTF-8'), ip)          
        elif required_headers.items() <= headers.items():
            with open('whitelist.txt', 'r+') as whitelist:
                whitelist.write(ip+'\n')
            if request.method == 'GET':
                return forward(request.method, headers, None, ip) 
            elif request.method == 'POST':
                return forward(request.method, headers, request.data.decode('UTF-8'), ip)
        
        with open('blacklist.txt', 'r+') as blacklist:
            blacklist.write(ip+'\n')
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


def updateLists():
    threading.Timer(1.0, updateLists).start()
    blacklistList.clear()
    with open('blacklist.txt', 'r') as blacklist:
        for line in blacklist:
            blacklistList.append(line.replace("\n", ""))
    whitelistList.clear()
    with open('whitelist.txt', 'r') as whitelist:
        for line in whitelist:
            whitelistList.append(line.replace("\n", ""))
            

if __name__ == "__main__":    
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", action="store", required=False)
    parser.add_argument("-c", "--cert", action="store", required=False)
    parser.add_argument("-k", "--key", action="store", required=False)
    parser.add_argument("-t", "--target", action="store", default="http://127.0.0.1:8000")
    parser.add_argument("-d", "--droptarget", action="store", default="https://google.com")
    parser.add_argument("-u", "--URI", action="store", default="")

    args = parser.parse_args()
    port = int(args.port)
    cert = str(args.cert)
    key = str(args.key)
    target = str(args.target)
    droptarget = str(args.droptarget)
    URI = str(args.URI)

    updateLists()

    app = create_app()
    if port == 443:
        app.run(host="0.0.0.0", port=port, ssl_context=(cert, key))
    else:
        app.run(host="0.0.0.0", port=port)