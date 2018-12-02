# https://msdn.microsoft.com/en-us/library/cc240469.aspx
import enum


class RDP_PROTOCOL(enum.IntFlag):
	PROTOCOL_RDP = 0x00
	PROTOCOL_SSL = 0x01
	PROTOCOL_HYBRID = 0x02
	PROTOCOL_RDSTLS = 0x04
	PROTOCOL_HYBRID_EX = 0x08

################################  Client X.224 Connection Request PDU ############################
class RDP_NEG_REQ_FAGS(enum.IntFlag):
	RESTRICTED_ADMIN_MODE_REQUIRED = 0x01
	REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02
	CORRELATION_INFO_PRESENT = 0x08

class RDP_NEG_REQ:
	def __init__(self):
		self.type = None
		self.flags = None
		self.length = None
		self.requestedProtocols = None

class RDP_NEG_CORRELATION_INFO:
	def __init__(self):
		self.type = None
		self.flags = None
		self.length = None
		self.correlationId = None
		self.reserved = None

class X224ConnectionRequest:
	def __init__(self):
		self.tpktHeader = None
		self.x224Crq = None
		self.routingToken = None
		self.cookie = None
		self.rdpNegReq = None
		self.rdpCorrelationInfo = None


################################ Server X.224 Connection Confirm PDU ############################

class RDP_NEG_RSP_FLAGS(enum.IntFlag):
	EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
	DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02
	NEGRSP_FLAG_RESERVED = 0x04
	RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08
	REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10

class RDP_NEG_RSP:
	def __init__(self):
		self.type= None
		self.flags= None
		self.length= None
		self.selectedProtocol= None

class RDP_NEG_FAILURE:
	def __init__(self):
		self.type= None
		self.flags= None
		self.length= None
		self.failureCode= None

class X224ConnectionConfirm:
	def __init__(self):
		self.tpktHeader = None
		self.x224Ccf = None
		self.rdpNegData = None

########################## Client MCS Connect Initial PDU with GCC Conference Create Request ###############
class TS_UD_HEADER:
	def __init__(self):
		self.type = None
		self.length = None

class MCSConnect:
	def __init__(self):
		self.tpktHeader = None
		self.x224Data = None
		self.mcsCi = None
		self.gccCCrq = None
		self.clientCoreData = None
		self.clientSecurityData = None
		self.clientNetworkData = None
		self.clientClusterData = None
		self.clientMonitorData = None
		self.clientMessageChannelData = None
		self.clientMultitransportChannelData = None
		self.clientMonitorExtendedData = None
