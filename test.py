from email import message_from_binary_file
from gen2 import *

# if __name__ == "__Main__":
# pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader(BodyLen=32) / \
    # AddComplexInstrument(TemplateID=13400, NoLegs=2)
# ls(pkt[AddComplexInstrument])

pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/AddComplexInstrument(NoLegs=2)

pkt[PacketHeader].MessageHeader = MessageHeaderComp(BodyLen=32)
pkt[AddComplexInstrument].MessageHeader = MessageHeaderComp(TemplateID=13400)
pkt[AddComplexInstrument].InstrmtLegGrp = [InstrmtLegGrpComp(LegPrice=114), InstrmtLegGrpComp(LegPrice=514)]
# ls(ppkt)
pkt.show2()
wrpcap('./trial.pcap', pkt, append=False)
