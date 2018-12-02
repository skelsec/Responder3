#https://github.com/FreeRDP/FreeRDP/blob/eb1727bb875f27d7e02d47e0cc02f2e6546153e1/libfreerdp/core/tpdu.c
import enum

class X224_TPDU_TYPE(enum.Enum):
	X224_TPDU_CONNECTION_REQUEST = 0xE0
	X224_TPDU_CONNECTION_CONFIRM = 0xD0
	X224_TPDU_DISCONNECT_REQUEST = 0x80
	X224_TPDU_DATA = 0xF0
	X224_TPDU_ERROR = 0x70

class TPDU:
	def __init__(self):
		self.LI = None #1 byte
		self.Code = None#1 byte
		self.DST_REF = None#2 byte
		self.SRC_REF = None#2 byte
		self.Class = None#1 byte