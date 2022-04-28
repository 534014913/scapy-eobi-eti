

import sys
import pprint
import xml.etree.ElementTree as ET

PATH_TO_SPEC = "./eobi/eobi.xml"

root = ET.parse(PATH_TO_SPEC).getroot()

xml_application_messages = root.find("ApplicationMessages")

hdr_node = root.find(
	".//ApplicationMessages/ApplicationMessage/[@name='PacketHeader']")

def parse_eobi_xml(xml_msg):
	if 	 xml_msg.tag == 'Model':
		return parse_model(xml_msg)
	elif xml_msg.tag == 'MessageFlows':
		return parse_message_flows(xml_msg)
	elif xml_msg.tag == 'ApplicationMessages':
		return parse_application_messages(xml_msg)
	elif xml_msg.tag == 'Structures':
		return parse_structures(xml_msg)
	elif xml_msg.tag == 'Structure':
		return parse_structure(xml_msg)
	elif xml_msg.tag == 'DataTypes':
		return parse_data_types(xml_msg)
	elif xml_msg.tag == 'DataType':
		return parse_data_type(xml_msg)
	elif xml_msg.tag == 'ApplicationMessage':
		return parse_application_message(xml_msg)
	elif xml_msg.tag == 'Group':
		return parse_group(xml_msg)
	elif xml_msg.tag == 'Member':
		return parse_member(xml_msg)
	elif xml_msg.tag == "ValidValue":
		return parse_valid_value(xml_msg)
	else:
		sys.exit(f'{xml_msg.tag} does not any existing tag')

def parse_model(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields

	return base_dict

def parse_message_flows(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_application_message(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0: base_dict['fields'] = fields	

	return base_dict

def parse_application_messages(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_group(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields =  []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0: base_dict['fields'] = fields
	return base_dict


def parse_member(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_valid_value(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_structures(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_structure(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_data_types(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

def parse_data_type(xml_msg):
	base_dict = xml_msg.attrib
	base_dict['tag'] = xml_msg.tag
	fields = []

	for child in xml_msg:
		fields.append(parse_eobi_xml(child))

	if len(fields) != 0:
		base_dict['fields'] = fields
	return base_dict

pprint.pprint(parse_eobi_xml(root))
