import nmap
import sys
import os
import requests
import json
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor #create a pool of worker threads that can execute tasks asynchronously.

# Function to retrieve the banner for a given IP address and port
def retBanner(ip,port):
	try:
		socket.setdefaulttimeout(2)
		sock = socket.socket()
		sock.connect((ip,port))
		banner = sock.recv(1024)
		return banner
	except:
		return

# Function to check if a banner matches a known vulnerability
def checkVulns(banner,filename):
	f = open(filename,"r")
	for line in f.readlines():
		if line.strip('\n') in banner:
			print("[+] Server is Vulnerable: " + "banner.strip('\n')")

# Function to retrieve the CVSS score for a given CVE ID
def getCVSSScore(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.content.decode())
        cvss_score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
        return cvss_score
    else:
        return 0

# Function to scan a single host and port
def scan(host, port):
    banner = retBanner(host, port)
    if banner:
        print(f"[+] {host}/{port} : {banner}")
        checkVulns(banner, filename)
        cve_id = banner.split(b" ")[0].decode("utf-8")
        cvss_score = getCVSSScore(cve_id)
        print(f"[+] CVSS Score for {cve_id}: {cvss_score}")

# Main function
def main():
	# Check if the filename is provided as a command-line argument
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		if not os.path.isfile(filename):
			print('[-] File Doesnt Exist!')
			exit(0)
		if not os.access(filename, os.R_OK):
			print('[-] Access Denied!')
			exit(0)
	else:
		print(f'[-] Usage: {sys.argv[0]} <vuln filename>')
		exit(0)
	
	# Define the list of hosts and ports to scan
	hosts = [f"192.168.1.{x}" for x in range(16,37)]
	ports = [22,21,25,80,110,443,445,135]
	
	# Use multithreading to speed up the scan
 # to speed up the scan by scanning multiple ports on multiple hosts simultaneously. 
	with ThreadPoolExecutor(max_workers=10) as executor:
		for host in hosts:
			for port in ports:
				executor.submit(scan, host, port)

if __name__ == '__main__':
    main()
