#!/usr/bin/env python3
"""
Author: Jeff Cagle
Date: 2025-05-15
Title: Nmap XML Web Target Parser + ffuf Fuzzer
Version: 1.0
Description:
    This script parses Nmap XML output to identify web-facing services (HTTP/HTTPS),
    then runs ffuf for directory fuzzing against discovered hosts and ports. It includes
    options for recursion, rate limiting, and stealth header customization.

Requirements:
    - ffuf
    - Python 3.x
    - Nmap with XML output enabled (-oX)

License: GNU GPL
"""

import os
import subprocess
import xml.etree.ElementTree as ET

WEB_PORTS_HTTP = [80, 8080, 8000]
WEB_PORTS_HTTPS = [443, 8443]

def parse_nmap_xml(file_path):
    print(f"[*] Parsing Nmap XML: {file_path}")
    tree = ET.parse(file_path)
    root = tree.getroot()

    targets = []

    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue

        ip = address.attrib["addr"]
        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            portid = int(port.attrib["portid"])
            state_elem = port.find("state")
            if state_elem is not None and state_elem.attrib.get("state") == "open":
                protocol = "https" if portid in WEB_PORTS_HTTPS else "http"
                targets.append((ip, portid, protocol))

    return targets

def run_ffuf(ip, port, protocol, wordlist_path, max_time):
    base_url = f"{protocol}://{ip}:{port}"
    url = f"{base_url}/FUZZ"
    print(f"[+] Running ffuf on {url}")

    output_file = f"ffuf_{ip}_{port}.json"

    cmd = [
        'ffuf',
        '-u', url,
        '-w', wordlist_path,
        '-mc', '200,204,301,302,403',
        '-t', '50',
	'-ac',
        '-recursion',  # Recursive fuzzing
	'-recursion-depth', '1',
	'-rate', '100',
	'-maxtime', max_time,
	'-s',
        '-json',
        '-o', output_file
    ]

    subprocess.run(cmd)

    print(f"[+] ffuf scan complete. Output saved to {output_file}")

def main():
    nmap_xml_path = input("Enter path to Nmap XML file: ").strip()
    wordlist_path = input("Enter path to wordlist file: ").strip()
    max_time = input("Enter a maxtime value to run ffuf: ").strip()

    if not os.path.exists(nmap_xml_path):
        print("[-] File not found.")
        return
        
    if not os.path.exists(wordlist_path):
    	print("[-] Wordlist not found.")
    	return

    targets = parse_nmap_xml(nmap_xml_path)

    if not targets:
        print("[!] No web targets found.")
        return

    for ip, port, protocol in targets:
        print(f"[*] Target: {ip}:{port} ({protocol})")
        run_ffuf(ip, port, protocol, wordlist_path, max_time)

if __name__ == "__main__":
    main()
