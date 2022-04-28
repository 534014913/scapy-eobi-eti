import sys
from scapy.all import sr1,IP, ICMP
import xml.etree.ElementTree as ET
root = ET.parse("./eobi/eobi.xml").getroot()

application_messages = root.find("ApplicationMessages")

def parse_message(xml_msg):
	if (xml_msg.tag == 'ApplicationMessage'):
		return parse_application_message(xml_msg)
	elif (xml_msg.tag == 'Group'):
		return parse_group(xml_msg)
	elif (xml_msg.tag == 'Member'):
		return parse_member(xml_msg)
	elif (xml_msg.tag == "ValidValue"):
		return parse_valid_value(xml_msg)
	else:
		sys.exit(f'{xml_msg.tag} does not any existing tag')
		
	
def parse_application_message(xml_msg):
	return xml_msg.attrib

def parse_group(xml_msg):
	return xml_msg.attrib

def parse_member(xml_msg):
	return xml_msg.attrib

def parse_valid_value(xml_msg):
	return xml_msg.attrib

hdr_node = root.find(
	".//ApplicationMessages/ApplicationMessage/[@name='PacketHeader']")

if __name__ == '__main__':
	print("Hello World")
