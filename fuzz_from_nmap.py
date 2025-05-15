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
    - gowitness

License: GNU GPL
"""

import os
import subprocess
import random
import json
import xml.etree.ElementTree as ET

WEB_PORTS_HTTP = [80, 8080, 8000]
WEB_PORTS_HTTPS = [443, 8443]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.68.0",
    "python-requests/2.25.1"
]

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

def choose_user_agent():
    return random.choice(USER_AGENTS)

def prepare_target_output_dir(ip, port):
    folder_name = f"{ip}_{port}"
    output_dir = os.path.join("output", folder_name)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def write_summary(ip, port, output_dir, output_file):
    summary_file = os.path.join(output_dir, "summary.txt")
    try:
        with open(output_file, "r") as f:
            ffuf_data = json.load(f)
        results = ffuf_data.get("results", [])

        with open(summary_file, "w") as f:
            f.write(f"Target: {ip}:{port}\n")
            f.write(f"Scan output: {output_file}\n")
            f.write("Matched paths:\n")
            for r in results:
                f.write(f"{r.get('url')}\n")

        print(f"[+] Summary written to {summary_file}")
    except Exception as e:
        print(f"[-] Failed to write summary for {ip}:{port}: {e}")

def run_gowitness(ip, port, protocol, output_dir):
    base_url = f"{protocol}://{ip}:{port}"
    workspace = os.path.join(output_dir, "gowitness_workspace")
    os.makedirs(workspace, exist_ok=True)

    urls_file = os.path.join(workspace, "urls.txt")
    urls = set()
    urls.add(base_url)

    # Attempt to read ffuf results and extract URLs
    ffuf_output = os.path.join(output_dir, "ffuf_results.json")
    if os.path.exists(ffuf_output):
        try:
            with open(ffuf_output, "r") as f:
                ffuf_data = json.load(f)
                for r in ffuf_data.get("results", []):
                    url = r.get("url")
                    if url:
                        urls.add(url)
        except Exception as e:
            print(f"[-] Could not parse ffuf results: {e}")

    # Write all URLs (base + paths) to file
    with open(urls_file, "w") as f:
        for url in sorted(urls):
            f.write(url + "\n")

    print(f"[+] Taking screenshots of {len(urls)} URLs with gowitness...")

    subprocess.run([
        "gowitness", "scan", "file",
        "-f", urls_file,
        "--chrome-path", "/usr/bin/chromium"
    ])

    print(f"[+] Screenshot saved (check ~/.gowitness/screenshots/ or working dir)")

def run_ffuf(ip, port, protocol, wordlist_path, max_time):
    url = f"{protocol}://{ip}:{port}/FUZZ"
    print(f"[+] Running ffuf on {url}")

    output_dir = prepare_target_output_dir(ip, port)
    output_file = os.path.join(output_dir, "ffuf_results.json")

    chosen_agent = choose_user_agent()

    cmd = [
        'ffuf',
        '-u', url,
        '-w', wordlist_path,
        '-mc', '200,204,301,302,403',
        '-t', '50',
	'-ac',
        '-recursion',  # Recursive fuzzing
	'-recursion-depth', '1',
	'-rate', '50',
	'-p', '0.05',
	'-maxtime', max_time,
	'-H', f'User-Agent: {chosen_agent}',
	'-s',
        '-json',
        '-o', output_file
    ]

    subprocess.run(cmd)

    print(f"[+] ffuf scan complete. Output saved to {output_file}")

    write_summary(ip, port, output_dir, output_file)
    run_gowitness(ip, port, protocol, output_dir)

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
        print(f"[*] Target: {ip}:{port} ({protocol})\n")
        run_ffuf(ip, port, protocol, wordlist_path, max_time)

if __name__ == "__main__":
    main()
