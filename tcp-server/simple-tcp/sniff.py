from scapy.all import *

# Script to sniff traffic between simple client and server 
capture = sniff(iface="lo",filter="tcp port 65535",prn=lambda x: x.summary() )

wireshark(capture)

