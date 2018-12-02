# https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/tpkt.c

class TPKT:
	def __init__(self):
		self.version = None
		self.reserved = None
		self.length = None
		