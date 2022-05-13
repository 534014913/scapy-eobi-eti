from eobi import *
import subprocess
import xml.etree.ElementTree as ET

XML_NAME = 'test_xml.xml'
PROTOCOL_NAME = 'eurex.derivatives.eobi.t7.v10.0.'

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


def quote_request_test():
    lst_qty = 25511
    side = 2
    sec_id = 78551

    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/QuoteRequest(SecurityID=sec_id, Side=side, LastQty=lst_qty)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[QuoteRequest].MessageHeader = MessageHeaderComp(TemplateID=13503)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))
        # print(xml.attrib)

        print('Testing for Quote Request Message Fields:')
        print_if_not_match('SecurityID', get_show(
            xml, 'securityid'), sec_id)
        print_if_not_match('Side', get_show(
            xml, 'side'), side)
        print_if_not_match('LastQty', get_show(
            xml, 'lastqty'), lst_qty / pow(10, 4))

    except subprocess.CalledProcessError as error:
        raise error

def cross_request_test():
    crx_type = 2
    ipt_src = 1
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader() /CrossRequest(CrossRequestType=crx_type, InputSource=ipt_src)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[CrossRequest].MessageHeader = MessageHeaderComp(TemplateID=13502)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))
        # print(xml.attrib)

        print('Testing for Cross Request Message Fields:')
        print_if_not_match('CrossRequestType', get_show(
            xml, 'crossrequesttype'), crx_type)
        print_if_not_match('InputSource', get_show(
            xml, 'inputsource'), ipt_src)

    except subprocess.CalledProcessError as error:
        raise error

def trade_report_test():
    mtch_typ = 5
    trd_cond = 596

    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader() / \
        TradeReport(MatchType=mtch_typ, TradeCondition=trd_cond)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[TradeReport].MessageHeader = MessageHeaderComp(TemplateID=13201)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        # print(result.stdout)
        
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))
        # print(xml.attrib)

        print('Testing for Trade Report Message Fields:')
        print_if_not_match('MatchType', get_show(
            xml, 'matchtype'), mtch_typ)
        print_if_not_match('TradeCondition', get_show(
            xml, 'tradecondition'), trd_cond)

    except subprocess.CalledProcessError as error:
        raise error

def trade_reversal_test():
    entries = 2
    md_etry_type1 = 5
    md_price1 = 100000000000000

    md_etry_type2 = 10
    md_price2 = 255555555555555

    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader() / \
        TradeReversal(NoMDEntries=entries)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[TradeReversal].MessageHeader = MessageHeaderComp(TemplateID=13200)
    pkt[TradeReversal].MDTradeEntryGrp = [MDTradeEntryGrpComp(MDEntryType=md_etry_type1, MDEntryPx=md_price1),
                                            MDTradeEntryGrpComp(MDEntryType=md_etry_type2, MDEntryPx=md_price2)]

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))
        # print(xml.attrib)
        print('Testing for Trade Reversal Message Fields:')
        print_if_not_match('NoMDEntries', get_show(xml, 'nomdentries'), entries)
        print_if_not_match('MDEntryType 1', get_show(xml, 'mdentrytype'), md_etry_type1)
        print_if_not_match('MDEntryPx 1', get_show(xml, 'mdentrypx'), md_price1 / pow(10, 8))

        xml = xml.findall(xml_path('mdtradeentrygrpcomp'))[1]
        print_if_not_match('MDEntryType 2', get_show(xml, 'mdentrytype'), md_etry_type2)
        print_if_not_match('MDEntryPx 2', get_show(xml, 'mdentrypx'), md_price2 / pow(10, 8))
    except subprocess.CalledProcessError as error:
        raise error

def order_add_test():
    disply_qty = 244330000
    price = 3123100000000
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/OrderAdd()
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[OrderAdd].MessageHeader = MessageHeaderComp(TemplateID=13100)
    pkt[OrderAdd].OrderDetails = OrderDetailsComp(DisplayQty=disply_qty, Price=price)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))

        print('Testing for Order Add Message Fields:')
        print_if_not_match('DisplayQty', get_show(
            xml, 'displayqty'), disply_qty / pow(10, 4))
        print_if_not_match('Price', get_show(
            xml, 'price'), price / pow(10, 8))
    except subprocess.CalledProcessError as error:
        raise error

def top_of_book_test():
    bid_px = 12300000000
    offer_px = 33200000000
    bid_size = 123400000
    offer_size = 114320000

    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/TopOfBook(BidPx=bid_px, OfferPx=offer_px, BidSize=bid_size, OfferSize=offer_size)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[TopOfBook].MessageHeader = MessageHeaderComp(TemplateID=13504)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))

        print('Testing for Top of Book Message Fields:')
        print_if_not_match('BidPx', get_show(
            xml, 'bidpx'), bid_px / pow(10, 8))
        print_if_not_match('OfferPx', get_show(
            xml, 'offerpx'), offer_px / pow(10, 8))
        print_if_not_match('BidSize', get_show(
            xml, 'bidsize'), bid_size / pow(10, 4))
        print_if_not_match('OfferSize', get_show(
            xml, 'offersize'), offer_size / pow(10, 4))
    except subprocess.CalledProcessError as error:
        raise error

def auciton_best_test():
    pste = 0
    oot = 1
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader()/AuctionBBO(PotentialSecurityTradingEvent=pste, OfferOrdType=oot)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[AuctionBBO].MessageHeader = MessageHeaderComp(TemplateID=13500)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))

        print('Testing for Auction Best Message Fields:')
        print_if_not_match('PotentialSecurityTradingEvent', get_show(
            xml, 'potentialsecuritytradingevent'), pste)
        print_if_not_match('OfferOrdType', get_show(
            xml, 'offerordtype'), oot) 
    except subprocess.CalledProcessError as error:
        raise error

def auction_clearing_test():
    imb = 45230000
    pste = 10
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader() / \
        AuctionClearingPrice(ImbalanceQty=imb, PotentialSecurityTradingEvent=pste)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[AuctionClearingPrice].MessageHeader = MessageHeaderComp(TemplateID=13501)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))

        print('Testing for Auction Clearing Message Fields:')
        print_if_not_match('PotentialSecurityTradingEvent', get_show(
            xml, 'potentialsecuritytradingevent'), pste)
        print_if_not_match('ImbalanceQty', get_show(
            xml, 'imbalanceqty'), imb / pow(10, 4))
    except subprocess.CalledProcessError as error:
        raise error

def product_state_change_test():
    sid = 6
    subid = 3
    status = 2
    indicator = 0
    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader() / \
        ProductStateChange(TradingSessionID=sid, TradingSessionSubID=subid, TradSesStatus=status, FastMarketIndicator=indicator)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[ProductStateChange].MessageHeader = MessageHeaderComp(
        TemplateID=13300)

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))

        print('Testing for Product State Change Message Fields:')
        print_if_not_match('TradingSessionID', get_show(
            xml, 'tradingsessionid'), sid)
        print_if_not_match('TradingSessionSubID', get_show(
            xml, 'tradingsessionsubid'), subid)
        print_if_not_match('TradSesStatus', get_show(xml, 'tradsesstatus'), status)
        print_if_not_match('FaseMarketIndicator', get_show(xml, 'fastmarketindicator'), indicator)
    except subprocess.CalledProcessError as error:
        raise error


def instrument_summary_test():
    update_time = 22313123151
    no_orders = 33
    sec_stat = 11
    sec_tra_stat = 209
    trd_event = 11
    high_px = 2233100000000
    mdentries = 1
    entry_px = 12312300000000
    entry_size = 7860000
    entry_type = 66
    trad_cond = 624

    pkt = IP()/UDP(sport=65333, dport=65333)/PacketHeader() / \
        InstrumentSummary(LastUpdateTime=update_time,
                            TotNoOrders=no_orders,
                            SecurityStatus=sec_stat,
                            SecurityTradingStatus=sec_tra_stat,
                            SecurityTradingEvent=trd_event,
                            HighPx=high_px,
                            NoMDEntries=mdentries)
    pkt[PacketHeader].MessageHeader = MessageHeaderComp(TemplateID=13005)
    pkt[InstrumentSummary].MessageHeader = MessageHeaderComp(
        TemplateID=13601)
    pkt[InstrumentSummary].MDInstrumentEntryGrp = [MDInstrumentEntryGrpComp(MDEntryPx=entry_px,
                                                                                MDEntrySize=entry_size,
                                                                                MDEntryType=entry_type,
                                                                                TradeCondition=trad_cond)]

    wrpcap('./test.pcap', pkt, append=False)
    try:
        result = subprocess.run(
            ['tshark', '-V', '-r', 'test.pcap'], check=True, capture_output=True, text=True)
        if print_if_error(result.stdout):
            return
        result = subprocess.run(
            "tshark -T pdml -r test.pcap".split(" "), check=True, capture_output=True, text=True)
        xml = ET.fromstring(result.stdout)
        xml = xml.find(xml_path('message'))

        print('Testing for Instrument Summary Message Fields:')
        print_if_not_match('LastUpdateTime', get_show(
            xml, 'lastupdatetime'), update_time)
        print_if_not_match('TotNoOrders', get_show(
            xml, 'totnoorders'), no_orders)
        print_if_not_match('SecurityStatus', get_show(
            xml, 'securitystatus'), sec_stat)
        print_if_not_match('SecurityTradingEvent', get_show(
            xml, 'securitytradingevent'), trd_event)
        print_if_not_match('SecurityTradingStatus', get_show(
            xml, 'securitytradingstatus'), sec_tra_stat)
        print_if_not_match('HighPx', get_show(xml, 'highpx'), high_px / pow(10, 8))
        print_if_not_match('NoMDEntries', get_show(xml, 'nomdentries'), mdentries)

        print_if_not_match('MDEntryPx', get_show(xml, 'mdentrypx'), entry_px / pow(10, 8))
        print_if_not_match('MDEntrySize', get_show(xml, 'mdentrysize'), entry_size / pow(10, 4))
        print_if_not_match('MDEntryType', get_show(xml, 'mdentrytype'), entry_type)
        print_if_not_match('TradeCondition', get_show(xml, 'tradecondition'), trad_cond)
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
    quote_request_test()
    cross_request_test()
    trade_report_test()
    trade_reversal_test()
    order_add_test()
    top_of_book_test()
    auciton_best_test()
    auction_clearing_test()
    product_state_change_test()
    instrument_summary_test()

    subprocess.run("rm test.pcap".split(' '))
