import imp
from gen2 import *
import subprocess
import xml.etree.ElementTree as ET

# if __name__ == "__Main__":
# pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader(BodyLen=32) / \
    # AddComplexInstrument(TemplateID=13400, NoLegs=2)
# ls(pkt[AddComplexInstrument])

XML_NAME = 'test_xml.xml'

pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/AddComplexInstrument(NoLegs=2)

pkt[PacketHeader].MessageHeader = MessageHeaderComp(BodyLen=32)
pkt[AddComplexInstrument].MessageHeader = MessageHeaderComp(TemplateID=13400)
pkt[AddComplexInstrument].InstrmtLegGrp = [InstrmtLegGrpComp(LegPrice=114000000), InstrmtLegGrpComp(LegPrice=514000000)]
# ls(ppkt)
# pkt.show2()
# wrpcap('./trial.pcap', pkt, append=False)

def print_if_error(sample_out):
    if sample_out is not None and  'Lua Error' in sample_out:
        idx = sample_out.index('Lua Error')
        print(f'''\x1b[0;37;41mThere is an error with the following message: \n{sample_out[idx:]} \x1b[0m''', file=sys.stderr)
        return True
    return False


def add_compliex_instrument_test():
    try:
        result = subprocess.run(['tshark', '-V', '-r', 'trial.pcap'], check=True, capture_output=True, text=True)
        print("stdout is:")
        print(result.stdout)
        print("")
        print("stderr: ")
        print(result.stderr)
        print_if_error(result.stderr)
    except subprocess.CalledProcessError as error:
        print(error.stdout)
        print(error.stderr)
        raise error

def packet_header_test():
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()
    pkt[PacketHeader].MessageHeader = MessageHeaderComp()
    wrpcap('./trial.pcap', pkt, append=False)
    try:
        result = subprocess.run(['tshark', '-V', '-r', 'trial.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        
    except subprocess.CalledProcessError as error:
        raise error

def expected_to_fail():
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/AddComplexInstrument(NoLegs=4)

    pkt[PacketHeader].MessageHeader = MessageHeaderComp(BodyLen=32)
    pkt[AddComplexInstrument].MessageHeader = MessageHeaderComp(TemplateID=13400)
    pkt[AddComplexInstrument].InstrmtLegGrp = [InstrmtLegGrpComp(LegPrice=114000000), InstrmtLegGrpComp(LegPrice=514000000)]
    pkt[AddComplexInstrument].MessageHeader.BodyLen = 11;

    wrpcap('./trial.pcap', pkt, append=False)

    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'trial.pcap'], check=True, capture_output=True, text=True)
        print_if_error(result.stdout)
    except subprocess.CalledProcessError as error:
        print(error.stdout)
        print(error.stderr)
        raise error

if __name__ == '__main__':
    # add_compliex_instrument_test()
    expected_to_fail()
    print("Hello, World!")
