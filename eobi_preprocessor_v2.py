# Code adopted from python-eti on github with the following license
# SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# NB: The generated code is licensed differently, i.e. it is
# licensed under the permissive Boost Software License.

from re import U
import xml.etree.ElementTree as ET
import pprint

from sklearn.cluster import k_means

PATH_TO_SPEC = "./eobi/eobi.xml"
PATH_TO_ETI_SPEC = "./T7_R-2/eti_derivatives.xml"

root = ET.parse(PATH_TO_SPEC).getroot()

# some test node that can be removed
xml_application_message = root.find("ApplicationMessages")
hdr_node = root.find(".//ApplicationMessages/ApplicationMessage/[@name='PacketHeader']")

def get_data_types(xml_tree):
	root = xml_tree.getroot()
	dlist = root.find('DataTypes')
	dt = {}
	for dt_obj in dlist:
		dt[dt_obj.get('name')] = dt_obj

	return dt	

def get_structrue(xml_tree):
	root = xml_tree.getroot()
	slist = root.find('Structures')
	st = {}
	for s_obj in slist:
		st[s_obj.get('name')] = s_obj

	return st

# st the the dict from name to the structure object
def get_templates(st):
	ts = []
	for k,v in st.items():
		if v.get('type') == 'Message':
			ts.append((int(v.get('numericID')), k))
	ts.sort()
	return ts
	
def get_usages(xml_tree):
	def scan(m, us, p=''):
		for f in m:
			u = f.get('usage')
			if u is not None:
				us[p+m.get('name'), f.get('name')] = u
			elif f.tag == 'Group':
				scan(f, us, m.get('name') + '.')

	us = {}
	rt = xml_tree.getroot()
	ms = rt.find('ApplicationMessages')
	for m in ms:
		scan(m, us)
	return us

def get_message_flows(xml_tree):
	def parse_mf(cs, field=None):
		xs = []
		for c in cs:
			cond = None
			if field is not None:
				cond = f'{field} is {c.get("condition")}'
			if c.tag == 'Node':
				xs.append((None, cond, parse_mf(c, field=c.get('name'))))
			else:
				xs.append((c.get('name'), cond, parse_mf(c)))
		return xs

	rt = xml_tree.getroot()
	mfs = rt.find('MessageFlows')
	mf = {}
	for  mf_obj in mfs:
		m = mf_obj.find('Message')
		mf[m.get('name')] = parse_mf(m)
	return mf

def main():
	xml_tree = ET.parse(PATH_TO_ETI_SPEC)
	root = ET.parse(PATH_TO_SPEC).getroot()
	info = (xml_tree.getroot().get('name'), xml_tree.getroot().get('version'))

	dt = get_data_types(xml_tree)
	st = get_structrue(xml_tree)
	ts = get_templates(st)
	# pprint.pprint(get_templates(st))

	us = get_usages(xml_tree)
	mf = get_message_flows(xml_tree)
	pprint.pprint(mf)

if __name__ == '__main__':
	main()
