```
d8888b. d8b   db .d8888.        .d8888. d8888b.  .d88b.   .d88b.  d88888b d88888b d8888b.
88  `8D 888o  88 88'  YP        88'  YP 88  `8D .8P  Y8. .8P  Y8. 88'     88'     88  `8D
88   88 88V8o 88 `8bo.          `8bo.   88oodD' 88    88 88    88 88ooo   88ooooo 88oobY'
88   88 88 V8o88   `Y8b. C8888D   `Y8b. 88~~~   88    88 88    88 88~~~   88~~~~~ 88`8b
88  .8D 88  V888 db   8D        db   8D 88      `8b  d8' `8b  d8' 88      88.     88 `88.
Y8888D' VP   V8P `8888Y'        `8888Y' 88       `Y88P'   `Y88P'  YP      Y88888P 88   YD

```

### DNS spoofer is a man-in-the-middle attack. it spoofs the target and get all the reqiested dns from the target

# Dependecies

- python3
- scapy (PIP3)
- nmap

# Suppports

- Linux
- Mac Os

# Usage

```
usage: spoofer.py [-h] [-t TARGET] -g GATEWAY -i INTERFACE [-v] [-l] [-o]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Specify the target IP
  -g GATEWAY, --gateway GATEWAY
                        Specify the gateway
  -i INTERFACE, --iface INTERFACE
                        Specify the interface
  -v, --verbose         Show all DNS
  -l, --ls              List all the target names and IP connected to local network
  -o, --save            saves all the searched DNS to a file

```

# Screenshots

<div align=center><img src="dns.png"></div>
<div align=center><img src="dnsLs.png"></div>
<div align=center><img src="dnsSave.png"></div>
