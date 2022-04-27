import sys
from scapy.all import sr1,IP, ICMP
import xml.etree.ElementTree as ET
root = ET.parse("./eobi/eobi.xml").getroot()

application_messages = root.find("ApplicationMessages")

def parse_message(msg):
	if (msg.tag == 'ApplicationMessage'):
		return parse_application_message(msg)
	elif (msg.tag == 'Group'):
		return parse_group(msg)
	elif (msg.tag == 'Member'):
		return parse_member(msg)
	elif (msg.tag == "ValidValue"):
		return parse_valid_value(msg)
	else:
		sys.exit(f'{msg.tag} does not any existing tag')
		
	
def parse_application_message(msg):
	return msg.attrib

def parse_group(msg):
	return msg.attrib

def parse_member(msg):
	return msg.attrib

def parse_valid_value(msg):
	return msg.attrib

hdr_node = root.find(
	".//ApplicationMessages/ApplicationMessage/[@name='PacketHeader']")

if __name__ == '__main__':
	print("Hello World")
