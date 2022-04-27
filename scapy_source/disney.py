from scapy.all import *


class Disney(Packet):
	name = "DisneyPacket "
	fields_desc = [ShortField("mickey", 5),
					XByteField("minnie", 3),
					IntEnumField("donald", 1,
								{1: "happy", 2: "cool", 3: "angry"})]
