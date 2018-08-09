# gosslstrip
Golang SSL stripping proxy designed for DNS/ARP spoofing attacks.

## How It Works
All connections to the gosslstrip server will be proxied to the legitimate server (using HTTPS) to keep the victim on an unencrypted (HTTP) connection. This allows the eavesdropping and logging of URLs, headers, cookies and POST data. The gosslstrip server will also remove certain security headers, cookie flags, and rewrite links to prevent the victim from upgrading to an encrypted connection.