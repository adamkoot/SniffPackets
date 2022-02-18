import os
import sys
from scapy.config import conf
from scapy.layers.eap import EAPOL
from scapy.sendrecv import send, sendp, sr, srloop, sr1, sniff
from scapy.utils import wrpcap, rdpcap, hexdump

from scapy.all import *
def capturePacket()->None:
    """
    The function captures 10 recent IP packets and put source and destination addresses into pand$
    """
    conf.iface = 'mon1'
    pkts = sniff(filter="wlan proto 0x888e", count=4)
    wrpcap('filename.pcap', pkts, append=True)



pkts = rdpcap('file3.pcap')
a = 0
for n in range(len(pkts)):
    if pkts[n].haslayer(EAPOL):
        a +=1
    if a == 4:
       os.system(f"sudo kill {p.pid}")
       break