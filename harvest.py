__author__ = 'catatonic'

from scapy.all import *
import urllib
from subprocess import Popen

def monitor(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4 and len(pkt.info) == 32:
	print "Detected candidate packet for AP with MAC: %s" %(pkt.addr2)
	dec = Popen(['openssl', 'rsautl', '-decrypt', '-inkey', 'tvd.pem'], stdin=subprocess.PIPE)
	dec.stdin.write(pkt.info)
	dec.stdin.close()
	dec.wait()

conf.iface = 'wlan0mon'
print '[*] Monitoring'
sniff(prn=monitor, store=0)
