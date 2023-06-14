import nmap
import hashlib
from scapy.all import *
from modbus_tk import modbus_tcp

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

# Function to crack a password hash using a wordlist file
def crack_password(password_hash, wordlist_file):
    with open(wordlist_file, 'r') as f:
        for line in f:
            line = line.strip()
            if hashlib.md5(line.encode()).hexdigest() == password_hash:
                return line
    return None

# Function to generate Modbus traffic using Scapy and modbus_tk
def generate_modbus_traffic():
    pkt = IP(dst="192.168.1.1")/TCP(dport=502)/ModbusADU(unit=1)/ModbusPDU(function_code=3, starting_address=0, quantity=1)
    resp = sr1(pkt)
    if resp:
        print(resp.summary())
        client = modbus_tcp.TcpMaster(host="192.168.1.1", port=502)
        client.open()
        response = client.execute(1, cst.READ_HOLDING_REGISTERS, 0, 1)
        print(response)
        client.close()

# Function to scan a single host and port
def scan(host, port, filename):
    banner = retBanner(host, port)
    if banner:
        print(f"[+] {host}/{port} : {banner}")
        checkVulns(banner, filename)
        cve_id = banner.split(b" ")[0].decode("utf-8")
        cvss_score = getCVSSScore(cve_id)
        print(f"[+] CVSS Score for {cve_id}: {cvss_score}")
        password_hash = hashlib.md5(b"password").hexdigest()
        password = crack_password(password_hash, "wordlist.txt")
        if password:
            print(f"[+] Password for hash {password_hash}: {password}")
        generate_modbus_traffic()

# Function to discover services and hosts available on the network using Nmap
def discover_network():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sP')

    # Print the results
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                scan(host, port, filename)

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
	
	hosts = [f"192.168.1.{x}" for x in range(16,37)]
	ports = [22,21,25,80,110,443,445,135]
	
	# Use multithreading to speed up the scan
	with ThreadPoolExecutor(max_workers=10) as executor:
		for host in hosts:
			for port in ports:
				executor.submit(scan, host, port, filename)

if __name__ == '__main__':
    discover_network()
