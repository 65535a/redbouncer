import os
import argparse
import requests
from flask import Flask, request, redirect
import ast

target = ""
droptarget = ""

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(dict(DEBUG=True))
    app.config.update(config or {})

    required_headers = {}

    with open("headers.txt", "r") as f:
        data = f.read()
        required_headers = ast.literal_eval(data)

    @app.route("/", methods = ['GET', 'POST'])
    def bouncer():
        ip = request.remote_addr
        headers = dict(request.headers)

        with open('blacklist.txt', 'r+') as blacklist:
            if ip in blacklist.read():
                return redirect(droptarget)

        with open('whitelist.txt', 'r+') as whitelist:
            if ip in whitelist.read():
                if request.method == 'GET':
                    return forward(request.method, request.headers, None) 
                elif request.method == 'POST':
                    return forward(request.method, request.headers, request.data.decode('UTF-8'))          
            elif required_headers.items() <= headers.items():
                whitelist.write(ip+'\n')
                if request.method == 'GET':
                    return forward(request.method, request.headers, None) 
                elif request.method == 'POST':
                    return forward(request.method, request.headers, request.data.decode('UTF-8'))
        
        with open('blacklist.txt', 'r+') as blacklist:
            blacklist.write(ip+'\n')
        return redirect(droptarget)

    return app

def forward(method, headers, data):

    if method == 'GET':
        r = requests.get(target, headers=headers)
        return r.text
    elif method == 'POST':
        r = requests.post(target, headers=headers, data=data)
        return r.text
    else:
        return "Bad request", 400


if __name__ == "__main__":    
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", action="store", default="8000")
    parser.add_argument("-c", "--cert", action="store", default="./cert.pem")
    parser.add_argument("-k", "--key", action="store", default="./key.pem")
    parser.add_argument("-t", "--target", action="store", default="http://127.0.0.1:8000")
    parser.add_argument("-d", "--droptarget", action="store", default="https://google.com")

    args = parser.parse_args()
    port = int(args.port)
    cert = str(args.cert)
    key = str(args.key)
    target = str(args.target)
    droptarget = str(args.droptarget)

    app = create_app()
    app.run(host="0.0.0.0", port=port, ssl_context=(cert, key))
