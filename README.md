# Essential-Blocks-4.4.3---Unauthenticated-Local-File-Inclusion
The plugin does not prevent unauthenticated attackers from overwriting local variables when rendering templates over the REST API, which may lead to Local File Inclusion attacks.


# Usage:

```
usage: PoC.py [-h] -u URL [-p PAYLOAD]

Essential Blocks < 4.4.3 - Unauthenticated Local File Inclusion

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target WordPress site URL (e.g., http://192.168.100.74:888/wordpress)
  -p PAYLOAD, --payload PAYLOAD
                        File to read (default: /etc/passwd)

```

