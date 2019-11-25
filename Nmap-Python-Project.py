#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Requirement: pip install python-nmap

# Global imports
import nmap
import sys
import socket

# variable name for the Nmap scanner to be called
scanner = nmap.PortScanner()

print("""
            ███╗   ██╗███╗   ███╗ █████╗ ██████╗            
            ████╗  ██║████╗ ████║██╔══██╗██╔══██╗           
            ██╔██╗ ██║██╔████╔██║███████║██████╔╝           
            ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝            
            ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║                
            ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝                
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
""")
                                                            
print("        -----------------Welcome!------------------")
print("        -------------------------------------------")
# validate and print out the Nmap version
print("               Your Nmap version is",scanner.nmap_version())

# loop to check if the input is along the lines of an IP address
while True:
    # using socket to validate the IP address
    try:
        ip_addr = input("\nPlease enter the IP address you want to scan: ")
        socket.inet_aton(ip_addr)
    # If the IP is off in a major way the prompt will come back up    
    except socket.error:
        print("Oops! Invalid IP address format. Try again")
    # Break the loop if the user inputs the correct IP
    else:
        print("Valid IP address")
        break

option = input("""\nInput the number of the scan you want to run
--------------------------------------------------------
[1]--SYN/ACK Scan
[2]--UDP Scan
[3]--Full Scan
[4]--Registered Port Scan
[5]--EXIT \n""")

if option == '1':
    # This is a TCP based scan for the most well known ports
    print("SYN/ACK Scan")
    # print the IP that will be scanned
    print("Nmap scan report for: (",ip_addr,")")
    print('-------------------------------------')
    # Initializing the scanner in verbose mode with the TCP option -sS
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    # Prints out what protocol and ports that  are about to be scanned
    print(scanner.scaninfo())
    # Prints out all scanned protocols
    print(scanner[ip_addr].all_protocols())
    # Prints out all open ports found during scan
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    # Prints the status of the host up, down, or unknown
    print("IP address is (",scanner[ip_addr].state(),")")
    # Prints the results in a comma-seperated values format
    print(scanner.csv())
elif option == '2':
    # This is a UDP based scan for the most well known ports
    print("UDP Scan")
    print("Nmap scan report for: (",ip_addr,")")
    print("IP address is (",scanner[ip_addr].state(),")")
    print('-------------------------------------')
    # initializing the scanner in verbose mode with the UDP option -sU
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
    print("IP address is (",scanner[ip_addr].state(),")")
    print(scanner.csv())
elif option == '3':
    # This is a TCP based scan for the most well known ports
    print("Full Scan")
    print("Nmap scan report for: (",ip_addr,")")
    print('-------------------------------------')
    # Scan using default safe scripts, detect OS and services
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    print("IP address is (",scanner[ip_addr].state(),")")
    print(scanner.csv())
elif option == '4':
    # This is a TCP based scan for registered ports
    print("Registered port scan")
    print("Nmap scan report for: (",ip_addr,")")
    print('-------------------------------------')
    # Range of registered ports replace the well known ones here
    scanner.scan(ip_addr, '1024-49151', '-v -sS')
    print(scanner.scaninfo())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    print("Scan complete: IP address is (",scanner[ip_addr].state(),")")
    print(scanner.csv())
elif option >= '5':
    print("Quitting...")
    sys.exit(0)