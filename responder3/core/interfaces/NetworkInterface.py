import json
from responder3.core.commons import *

class NetworkInterface:

	def __init__(self):
		"""
		Container object to describe a network interface
		"""
		self.ifname = None
		self.ifindex = None # zone_indices in windows
		self.addresses = []
	
	def to_dict(self):
		return {
            "ifname": str(self.ifname),
            "ifindex": str(self.ifindex),
            "addresses": self.addresses
        }
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)

	def __repr__(self):
		return str(self)
		
	def __str__(self):
		t  = '== INTERFACE ==\r\n'
		t += 'Name: %s\r\n' % self.ifname
		t += 'ifindex: %s\r\n' % self.ifindex
		for addr in self.addresses:
			t += 'Address: %s\r\n' % str(addr)
		return t

