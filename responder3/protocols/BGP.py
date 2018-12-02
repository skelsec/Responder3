#https://tools.ietf.org/html/rfc4271
import enum
import io

class BGPMessageType(enum.Enum):
	OPEN = 1 
	UPDATE = 2
	NOTIFICATION = 3
	KEEPALIVE = 4

class BGPMessageParser:
	def __init__(self):
		pass

	@staticmethod
	def from_bytes(bbuff):
		return BGPMessage.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		pos = buff.tell()
		marker = buff.read(16)
		msg_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		msg_type = BGPMessageType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		buff.seek(pos, 0)
		msg = bgptype2class[msg_type].from_bytes(buff.read(msg_length))

		return msg

	@staticmethod
	async def from_streamreader(reader):
		t_marker = await readexactly_or_exc(reader, 16, timeout = self.timeout)
		t_length = await readexactly_or_exc(reader, 2, timeout = self.timeout)
		t_type = await readexactly_or_exc(reader, 1, timeout = self.timeout)
		msg_type = BGPMessageType(int.from_bytes(t_type, byteorder = 'big', signed = False))
		msg_length = int.from_bytes(t_length, byteorder = 'big', signed = False)
		rlen = msg_length - 19
		t_data = await readexactly_or_exc(reader, rlen, timeout = self.timeout)
		return bgptype2class[msg_type].from_bytes(t_marker + t_length + t_type + t_data)



# https://tools.ietf.org/html/rfc3392
# TODO: look for the actual types supported, the rfc doesnt say anything about that!
class BGPOptParameter:
	def __init__(self):
		self.type = None
		self.length = None
		self.value = None

	@staticmethod
	def from_bytes(bbuff):
		return BGPOptParameter.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		opt = BGPOptParameter()
		opt.type = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		opt.length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		opt.value = buff.read(opt.length)
		return opt

	def to_bytes(self):
		data = self.type.value.to_bytes(1, byteorder = 'big', signed = False)
		self.length = len(self.value)
		data += self.length.to_bytes(1, byteorder = 'big', signed = False)
		data += self.value
		return data

class BGPOpen:
	def __init__(self):
		self.marker = b'\xFF'*16
		self.msg_length = None
		self.msg_type = BGPMessageType.OPEN
		self.version = None
		self.my_AS = None
		self.hold_time = None
		self.bgp_identifier = None
		self.optional_parameters_length = None
		self.optional_parameters = []

	@staticmethod
	def from_bytes(bbuff):
		return BGPOpen.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		bo = BGPOpen()
		bo.marker = buff.read(16)
		bo.msg_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		bo.msg_type = BGPMessageType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		
		bo.version = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		bo.my_AS = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		bo.hold_time = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		bo.bgp_identifier = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		bo.optional_parameters_length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		if bo.optional_parameters_length > 0:
			rlen = bo.optional_parameters_length
			while rlen > 0:
				opt_param = BGPOptParameter.from_buffer(buff)
				bo.optional_parameters.append(opt_param)
				rlen -= opt_param.length

		return bo

	def to_bytes(self):
		data = self.version.to_bytes(1, byteorder = 'big', signed = False)
		data += self.my_AS.to_bytes(2, byteorder = 'big', signed = False)
		data += self.hold_time.to_bytes(2, byteorder = 'big', signed = False)
		data += self.bgp_identifier.to_bytes(4, byteorder = 'big', signed = False)

		opt_data = b''
		for opt in self.optional_parameters:
			opt_data += opt.to_bytes()

		self.optional_parameters_length = len(opt_data)
		data += self.optional_parameters_length.to_bytes(1, byteorder = 'big', signed = False)
		data += opt_data


		self.msg_length = len(data)
		
		hdr  = self.marker
		hdr += self.msg_length.to_bytes(2, byteorder = 'big', signed = False)
		hdr += self.msg_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return hdr + data

class WithdrawnRoute:
	def __init__(self):
		self.length = None
		self.prefix = None


	@staticmethod
	def from_bytes(bbuff):
		return WithdrawnRoute.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		wr = WithdrawnRoute()
		wr.length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		wr.prefix = buff.read(wr.length)
		return wr

	def to_bytes(self):
		return self.length.to_bytes(1, byteorder = 'big', signed = False) + self.prefix

class PathAttributeTypeFlag(enum.IntFlag):
	OPTIONAL = 128
	TRANSITIVE = 64
	PARTIAL = 32
	EXTENDED_LENGTH = 16
	UNUSED_3 = 8
	UNUSED_2 = 4
	UNUSED_1 = 2
	UNUSED_0 = 1

class PathAttributeTypeCode(enum.Enum):
	ORIGIN = 1
	AS_PATH = 2
	NEXT_HOP = 3
	MULTI_EXIT_DISC = 4
	LOCAL_PREF = 5
	ATOMIC_AGGREGATE = 6
	AGGREGATOR = 7
	COMMUNITIES = 8
	ORIGINATOR_ID = 9
	CLUSTER_LIST = 10


class PathAttributeType:
	def __init__(self):
		self.flags = None
		self.code = None

	@staticmethod
	def from_bytes(bbuff):
		return PathAttributeType.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		pat = PathAttributeType()
		pat.flags = PathAttributeTypeFlag(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		pat.code = PathAttributeTypeCode(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		return pat

	def to_bytes(self):
		return self.flags.value.to_bytes(1, byteorder = 'big', signed = False) + self.code.value.to_bytes(1, byteorder = 'big', signed = False)

class PathAttribute:
	def __init__(self):
		self.type = None
		self.length = None
		self.value = None

	@staticmethod
	def from_bytes(bbuff):
		return PathAttribute.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		pa = PathAttribute()
		pa.type = PathAttributeType.from_buffer(buff)
		if pa.type.flags & PathAttributeTypeFlag.EXTENDED_LENGTH:
			pa.length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		else:
			pa.length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		pa.value = pa.parse_value(buff.read(pa.length))
		return pa

	#override this method for implementing different types!
	def parse_value(self, bbuff):
		return bbuff

	#override this method for implementing different types!
	def serialize_value(self):
		return self.value

	def to_bytes(self):
		data = self.type.to_bytes()
		if self.type.flags & PathAttributeTypeFlag.EXTENDED_LENGTH:
			data += self.length.to_bytes(2, byteorder = 'big', signed = False)
		else:
			data += self.length.to_bytes(1, byteorder = 'big', signed = False)

		data += self.serialize_value()
		return data

class BGPNetworkLayerReachabilityInfo:
	def __init__(self):
		self.length = None
		self.prefix = None

	@staticmethod
	def from_bytes(bbuff):
		return BGPNetworkLayerReachabilityInfo.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		nlri = BGPNetworkLayerReachabilityInfo()
		nlri.length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		nlri.prefix = buff.read(nlri.length)
		return nlri

	def to_bytes(self):
		return self.length.to_bytes(1, byteorder = 'big', signed = False) + self.prefix

class BGPUpdate:
	def __init__(self):
		self.marker = b'\xFF'*16
		self.msg_length = None
		self.msg_type = BGPMessageType.UPDATE
		self.withdrawn_routes_length = None
		self.withdrawn_routes = []
		self.total_path_attribute_length = None
		self.path_attributes = []
		self.network_layer_reachability_information = None

	@staticmethod
	def from_bytes(bbuff):
		return BGPUpdate.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		bu = BGPUpdate()
		bu.marker = buff.read(16)
		bu.msg_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		bu.msg_type = BGPMessageType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))

		bu.withdrawn_routes_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		if bu.withdrawn_routes_length > 0:
			rlen = bu.withdrawn_routes_length
			while rlen > 0:
				wr = WithdrawnRoute.from_buffer(buff)
				bu.withdrawn_routes.append(wr)
				rlen -= wr.length

		bu.total_path_attribute_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		if bu.total_path_attribute_length > 0:
			rlen = bu.total_path_attribute_length
			while rlen > 0:
				pa = PathAttribute.from_buffer(buff)
				bu.path_attributes.append(pa)

		bu.network_layer_reachability_information = BGPNetworkLayerReachabilityInfo.from_buffer(buff)

		return bu

	def to_bytes(self):
		wr_data = b''
		for wr in self.withdrawn_routes:
			wr_data += wr.to_bytes()

		self.withdrawn_routes_length = len(wr_data)
		wr_len = self.withdrawn_routes_length.to_bytes(2, byteorder = 'big', signed = False)
		data = wr_len + wr_data

		pa_data = b''
		for pa in self.path_attributes:
			pa_data += pa.to_bytes()

		self.total_path_attribute_length = len(pa_data)
		tpal = self.total_path_attribute_length.to_bytes(2, byteorder = 'big', signed = False)
		data += tpal
		data += pa_data
		data += self.network_layer_reachability_information.to_bytes()
		self.msg_length = len(data)
		
		hdr  = self.marker
		hdr += self.msg_length.to_bytes(2, byteorder = 'big', signed = False)
		hdr += self.msg_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return hdr + data

class BGPKeepalive:
	def __init__(self):
		self.marker = b'\xFF'*16
		self.msg_length = 19
		self.msg_type = BGPMessageType.KEEPALIVE

	@staticmethod
	def from_bytes(bbuff):
		return BGPKeepalive.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		bk = BGPKeepalive()
		bk.marker = buff.read(16)
		bk.msg_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		bk.msg_type = BGPMessageType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		return bk

	def to_bytes(self):
		t  = self.marker
		t += self.msg_length.to_bytes(2, byteorder = 'big', signed = False)
		t += self.msg_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return t

class BGPError(enum.Enum):
	MESSAGE_HEADER = 1
	OPEN_MESSAGE = 2
	UPDATE_MESSAGE = 3
	HOLD_TIMER_EXPIRED = 4
	FINITE_STATE_MACHINE = 5
	CEASE = 6

class BGPErrorMessageHeader(enum.Enum):
	CONNECTION_NOT_SYNCHRONIZED = 1
	BAD_MESSAGE_LENGTH = 2
	BAD_MESSAGE_TYPE = 3

class BGPErrorOpenMessage(enum.Enum):  
	UNSUPPORTED_VERSION_NUMBER = 1
	BAD_PEER_AS = 2
	BAD_BGP_IDENTIFIER = 3
	UNSUPPORTED_OPTIONAL_PARAMETER = 4
	DEPRECATED_ERROR_CODE = 5
	UNACCEPTABLE_HOLD_TIME = 6

class BGPErrorUpdateMessage(enum.Enum):
	MALFORMED_ATTR_LIST = 1
	UNRECOGNIZED_WELL_KNOWN_ATTR = 2
	MISSING_WELL_KNOWN_ATTRIBUTE = 3
	ATTRIBUTE_FLAGS_ERROR = 4
	ATTRIBUTE_LENGTH_ERROR = 5
	INVALID_ORIGIN_ATTRIBUTE = 6
	DEPRECATED = 7
	INVALID_NEXT_HOP_ATTR = 8
	OPTIONAL_ATTRIBUTE_ERROR = 9
	INVALID_NETWORK_FILED = 10
	MALFORMED_AS_PATH = 11

class BGPNotification:
	def __init__(self):
		self.marker = b'\xFF'*16
		self.msg_length = None
		self.msg_type = BGPMessageType.NOTIFICATION
		self.error_code = None
		self.error_subcode = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return BGPNotification.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		nf = BGPNotification()
		nf.marker = buff.read(16)
		nf.msg_length = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		nf.msg_type = BGPMessageType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		nf.error_code = BGPError(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		if nf.error_code == BGPError.MESSAGE_HEADER:
			nf.error_subcode = BGPErrorMessageHeader(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		elif nf.error_code == BGPError.OPEN_MESSAGE:
			nf.error_subcode = BGPErrorOpenMessage(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		elif nf.error_code == BGPError.UPDATE_MESSAGE:
			nf.error_subcode = BGPErrorUpdateMessage(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		else:
			nf.error_subcode = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)

		nf.data = buff.read(self.msg_length - 21)
		return nf

	def to_bytes(self):
		data = error_code.value.to_bytes(1, byteorder = 'big', signed = False)
		if isinstance(self.error_subcode, enum.Enum):
			data += self.error_subcode.value.to_bytes(1, byteorder = 'big', signed = False)
		else:
			data += self.error_subcode.to_bytes(1, byteorder = 'big', signed = False)
		data += self.data

		self.msg_length = len(data)
		
		hdr  = self.marker
		hdr += self.msg_length.to_bytes(2, byteorder = 'big', signed = False)
		hdr += self.msg_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return hdr + data


bgptype2class = {
	BGPMessageType.OPEN : BGPOpen,
	BGPMessageType.UPDATE : BGPUpdate,
	BGPMessageType.NOTIFICATION : BGPNotification,
	BGPMessageType.KEEPALIVE : BGPKeepalive,
}