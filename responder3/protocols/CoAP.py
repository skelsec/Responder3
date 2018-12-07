# https://tools.ietf.org/html/rfc7252
# We got packets on packets on packets on packets

import io
import enum

from responder3.core.asyncio_helpers import *

class CoAPCode(enum.Enum):
	pass

class CoAPType(enum.Enum):
	CON = 0
	NON = 1
	ACK = 2
	RST = 3

class CoAPOptionNumber(enum.Enum):
	RESERVED_0 = 0
	IF_MATCH = 1
	URI_HOST = 3 
	ETAG = 4
	IF_NONE_MATCH = 5
	URI_PORT = 7 
	LOCATION_PATH = 8 
	URI_PATH = 11 
	CONTENT_FORMAT = 12 
	MAX_AGE = 14 
	URI_QUERY = 15 
	ACCEPT = 17 
	LOCATION_QUERY = 20 
	PROXY_URI = 35
	PROXY_SCHEME = 39
	SIZE1 = 60
	RESERVED_128 = 128
	RESERVED_132 = 132
	RESERVED_136 = 136
	RESERVED_140 = 140

class CoAPOption:
	def __init__(self):
		self.delta = None
		self.length = None
		self.value = None

	@staticmethod
	def from_bytes(bbuff, option_sum = 0):
		return CoAPOption.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff, option_sum = 0):
		t = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		delta = t >> 4
		length = t & 0b00001111
		if delta > 12:
			if delta == 13:
				delta = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
			elif delta == 14:
				delta = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
			else:
				raise Exception('Packet parse error! Opt delta')

		delta += option_sum #https://tools.ietf.org/html/rfc7252#section-3
		
		if length > 12:
			if length == 13:
				length = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
			elif length == 14:
				length = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
			else:
				raise Exception('Packet parse error! Opt length')

		value = buff.read(length)
		#
		opt = a
		return opt






class CoAPPacket:
	def __init__(self):
		self.version = None
		self.type = None
		self.token_length = None
		self.code = None
		self.message_id = None
		self.token = None
		self.options = []
		self.payload = None

	@staticmethod
	def from_bytes(bbuff):
		return CoAPPacket.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		packet = CoAPPacket()
		t = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		packet.version = t >> 6
		packet.type = (t >> 4) & 0b00000011
		packet.token_length = t & 0b00000011
		packet.code = CoAPCode(int.from_bytes(buff.read(1),byteorder = 'big', signed = False))
		packet.message_id = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		packet.token = int.from_bytes(buff.read(packet.token_length),byteorder = 'big', signed = False)

		packet.options = []
		packet.payload = None

		
	def to_bytes(self):