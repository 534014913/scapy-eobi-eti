from scapy import Packet, ShortField, XByteField, IntEnumField

class Protocol(Packet):
	name = "DisneyPacket"
	field_desc=[ShortField("mickey", 5),
				XByteField("minie", 3),
				IntEnumField("donald", 1, {1: "happy", 2: "cool", 3: "angry"})]
