from gen2 import *
import subprocess
import xml.etree.ElementTree as ET

# if __name__ == "__Main__":
# pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader(BodyLen=32) / \
    # AddComplexInstrument(TemplateID=13400, NoLegs=2)
# ls(pkt[AddComplexInstrument])

XML_NAME = 'test_xml.xml'
PROTOCOL_NAME = 'eurex.derivatives.eobi.t7.v10.0.'

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

def print_if_not_match(context, seen, expect):
    if float(seen) != expect: 
        print(f'''    \x1b[0;37;41m{context} should be {expect} but was {seen} \x1b[0m''')
        return False
    print(f'''    \x1b[0;37;42m{context} pass test \x1b[0m''')
    return True

def xml_path(field):
    path = f".//*[@name='{PROTOCOL_NAME}{field}']"
    # print(path)
    return path

def get_show(xml, field):
    return xml.find(xml_path(field)).get('show')

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
    appl_seq_num = 20
    partition_id = 50
    appl_seq_reset_indicator = 1
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader(ApplSeqNum=appl_seq_num, 
                                                            PartitionID=partition_id, 
                                                            ApplSeqResetIndicator=appl_seq_reset_indicator)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp()
    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run("tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        
        print('Testing for Packet Header Message Fields:')
        print_if_not_match('BodyLen', get_show(xml, 'headerlength'), 32)
        print_if_not_match('ApplSeqNum', get_show(xml, 'applseqnum'), appl_seq_num)
        print_if_not_match('PartitionID',get_show(xml, 'partitionid'), partition_id)
        print_if_not_match('ApplSeqResetIndicator', get_show(xml,'applseqresetindicator'), appl_seq_reset_indicator)
        
    except subprocess.CalledProcessError as error:
        raise error

def heart_beat_test():
    last_num = 1221;
    tml_id = 13001;
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/Heartbeat(LastMsgSeqNumProcessed=last_num)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[Heartbeat].MessageHeader = MessageHeaderComp(TemplateID=13001)
    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        # print(result.stdout)
        # f = open('tmp.xml', 'w')
        # f.write(result.stdout)
        # f.close()
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))
        # print(xml.attrib)

        print('Testing for Heartbeat Message Fields:')
        print_if_not_match('LastMsgSeqNumProcessed', get_show(xml, 'lastmsgseqnumprocessed'), last_num)
        print_if_not_match('TemplateID', get_show(xml, 'templateid'), tml_id)

    except subprocess.CalledProcessError as error:
        raise error
        
def execution_summary_test():
    agg_time = 5485454033
    req_time = 44859637
    last_px = 210734043
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/ExecutionSummary(AggressorTime=agg_time, RequestTime=req_time, LastPx=last_px)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[ExecutionSummary].MessageHeader = MessageHeaderComp(TemplateID=13202)
    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        # print(result.stdout)
        # f = open('tmp.xml', 'w')
        # f.write(result.stdout)
        # f.close()
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))
        # print(xml.attrib)

        print('Testing for Execution Summary Message Fields:')
        print_if_not_match('AggressorTime', get_show(
            xml, 'aggressortime'), agg_time)
        print_if_not_match('RequestTime', get_show(xml, 'requesttime'), req_time)
        print_if_not_match('LastPx', get_show(xml, 'lastpx'), last_px / pow(10, 8))

    except subprocess.CalledProcessError as error:
        raise error



def expected_to_fail():
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/AddComplexInstrument(NoLegs=4)

    pkt[PacketHeader].MessageHeader = MessageHeaderComp(BodyLen=32)
    pkt[AddComplexInstrument].MessageHeader = MessageHeaderComp(TemplateID=13400)
    pkt[AddComplexInstrument].InstrmtLegGrp = [InstrmtLegGrpComp(LegPrice=114000000), InstrmtLegGrpComp(LegPrice=514000000)]
    pkt[AddComplexInstrument].MessageHeader.BodyLen = 11;

    wrpcap('./trial.pcap', pkt, append=False)
    xml_obj = ET.parse()

    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'trial.pcap'], check=True, capture_output=True, text=True)
        print_if_error(result.stdout)
    except subprocess.CalledProcessError as error:
        print(error.stdout)
        print(error.stderr)
        raise error

if __name__ == '__main__':
    packet_header_test()
    heart_beat_test()
    execution_summary_test()
    # add_compliex_instrument_test()

