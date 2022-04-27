class BaseProtocolPaser:
	def __init__(self, basic_info):
		self.name = basic_info["name"];
		self.verison = basic_info["version"];
		self.build = basic_info["build"];


class EOBIParser(BaseProtocolPaser):
	def __init__(self, xml_info):
		super().__init__(self.get_basic_info(xml_info))
		self.message_flows = self.get_messsage_flows(xml_info.find("MessageFlows"))
		self.application_messages = self.get_applications_messages(xml_info.find("ApplicationMessages"))
		self.structure = self.get_structures(xml_info.find("Structures"))
		self.datatypes = self.get_datatypes(xml_info.find("DataTypes"))

	def get_basic_info(self, xml_info):
		pass

	def get_message_flows(self, app_msg_info):
		pass

	def get_structure(self, structure_info):
		pass

	def get_datatypes(self, datatypes_info):
		pass