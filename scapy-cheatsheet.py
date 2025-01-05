#!/usr/bin/env python3 

# Scapy cheatsheet 
from scapy.all import * 

# Constructing ethernet frame 

#packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.3.1") / TCP(dport=80)


# Display packet 
#packet.show()

# Send singular packet 
#send(packet)

# Send multiple packets  
#send(packet, count=10, inter=1) # inter is interval in seconds 

# Customize IP fields 
#packet = IP(src="192.168.3.104", dst="192.168.3.1") / ICMP()
#send(packet)

# Customize TCP fields 
#packet = IP(dst="192.168.3.1") / TCP(flags="5")

#ARP ping used to discover hosts on an ethernet network 
#ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /ARP(pdst="192.168.3.0/22"), timeout=2)

# View results from prior ARP ping 
#ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))

# Simplified version of arp ping 
#arping("192.168.3.0/24")

# Sniff packets 
#sniff_pack = sniff(count=5)
#sniff_pack.summary()

# Alternative form of sniffing 
#sniff(iface="ens18", prn=lambda x: x.summary())

# Sniff TCP : sniff only for TCP packets , sniff 5 packets 
#sniff(filter="tcp", count=5)

# ICMP ping 
#ans, unans = sr(IP(dst="192.168.3.100")/ICMP(), timeout=5)
# Return from ICMP ping 
#ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))

#wireshark(ans)
# TCP SYN ping 
#ans, unans = sr(IP(dst="192.168.3.101")/TCP(dport=80,flags="SA"))
# TCP ping summary 
#ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))

# UDP ping 
#ans, unans = sr(IP(dst="192.168.3.101")/UDP(dport=0))
# Summary  
#ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))


# TCP port scan 
#res, unans = sr( IP(dst="192.168.3.101") /TCP(flags="S", dport=(1,1024)) )
# Port Scan summary 
#res.nsummary( lfilter=lambda s,r: (r.haslayer(TCP) and r.getlayer(TCP).flags & 2))

# Sniff packets and open them in wireshark 
#packets= IP(src="192.168.3.104%ens18",dst="192.168.3.0/24")/ICMP()
#wireshark(packets)

# Send IP packet and open in wireshark 
#ans, unans = sr(IP(dst="192.168.3.100")/TCP(), timeout=5)
#ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))

#wireshark(ans)


# Forced ARP resolution 

target_ip = "192.168.3.104"
# Create ARP request 
#arp_req = ARP(pdst=target_ip)
# Send ARP request & receive response 
#arp_res = sr1(arp_req, timeout=2,verbose=True)

#if arp_res:
#    print(f"MAC address for {target_ip} is {arp_res.hwsrc}")

#else:
#    print("Coulden't resolve MAC for {target_ip}")

# Send packet to hw address resolved from prior ARP request 
#ether_send = Ether(dst=f"{arp_res.hwsrc}")
#ether_recv = sr1(ether_send, timeout=2,verbose=True)

# Layer different protocols 
#tcp_send = ether_send / IP(dst=f"{target_ip}") / TCP(dport=65535, flags="S")
ans, unans = sr(IP(dst="162.159.134.234")/ TCP(dport=443, flags="S"))
ans.summary(lambda s,r : r.sprintf("%IP.src% is alive"))

#tcp_res = sr1(tcp_send, timeout=5,verbose=False)
