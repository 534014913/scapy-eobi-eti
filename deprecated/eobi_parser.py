from scapy.all import *


class _EOBI_message(Packet):
	pass

class PacketHeader(_EOBI_message):
	name = "PacketHeader"
	fields_desc = [
		
	]
