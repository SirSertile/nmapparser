import argparse
import re

# Define the parser 
parser = argparse.ArgumentParser(description='Parse a list of urls or IPs from nmap scan results')
parser.add_argument('nmapfile', metavar='nmap_file', type=open, help='file to be parsed')

# Optional arguments
parser.add_argument('--port',type=str, metavar='port', help="Port to parse for")
parser.add_argument('--output', metavar='filepath', type=argparse.FileType('w', encoding='utf-8'), help="File to output the list IPs to") 
parser.add_argument('--url', action='store_true', help='Generate a URL list for Eyewitness')

# Parse the arguments 
args = parser.parse_args()

# Just for readability in the code
eyewitness = args.url

# Create a list to store scanned IPs structured as (IP, ports)
iplist = {} 
with args.nmapfile as f:
	raw = f.read()

# Split the port argument into a list 
try:
	ports = args.port.split(',')
except AttributeError:
	print("Port not specified, defaulting to eyewitness mode")
	ports = []
	eyewitness = True

if args.url and args.port:
	print("Eyewitness mode (-e) is incompatible with the --port option.\nExiting now . . . ")
	exit()

# Look for the header line "Nmap scan report for . . . "
for line in raw.split("\n"):
	# Handles parsing IPs
	if(line[0:20]=="Nmap scan report for"):
		currentip = line[21:]
		iplist[currentip]={'tcp':[],'udp':[]}
	
	# Handles parsing the ports 
	matchtext=re.search("\d*\/\w{3}.*open", line)
	try:
		port = matchtext.group().split(" ")[0]
		# The end of the string will always be a 3 letter code (TCP or UDP)
		if port[-3:] == "tcp":
			iplist[currentip]['tcp']+=[int(port[:-4])]
		elif port[-3:] == "udp":
			iplist[currentip]['udp']+=[int(port[:-4])]
	except:
		pass

# Setting up a list of web service ports for eyewitness mode 
http = [80,8080,8082,9080,10080,8888,8000]
https = [443,4443,8443,9443,10443]

output = ""
for ip in iplist:
	for port in iplist[ip]['tcp']:
		if eyewitness == True:
			if port in http:
				output += f'http://{ip}:{port}\n'
				print(f'http://{ip}:{port}')
			elif port in https:
				output += f'https://{ip}:{port}\n'
				print(f'https://{ip}:{port}')
		elif str(port) in ports:
			print(ip)
			output += ip + "\n"

