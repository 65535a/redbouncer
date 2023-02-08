Quick instructions:
- Install dependencies
- Add your Badger's http headers into the headers.txt file in json format (the key must start with CAPITAL letter)
- Generate an SSL key and a cert or use existing ones
- Run the main.py with suitable arguments (-h is your friend)

Requests from new IPs without proper headers are added straight into blacklist.txt which the script checks first during request handling. Requests from IPs which are found in whitelist.txt are proxied without the header check. If a request has valid headers, the IP is added to whitelist.txt.

To-do:
- Fix the bug which causes application to stop responding to new connections (probably caused by TCP socket exhaustion or something)
- Make a proper help message and documentation
- Implement proper logging
- Make forced SSL optional
- Make header handling case insensitive
- Handle black/whitelist in memory to avoid per-request disk operations
- Add X-Forwarded-For header to proxied requests to preserve originating IP
- Mute SSL warings while forced
- Blacklist an IP using wrong URI