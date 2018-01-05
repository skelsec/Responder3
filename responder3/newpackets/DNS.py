import enum

class DNSResponseCode(enum.Enum):
	NOERR = 0 #No error condition
	FORMATERR = 1 #Format error - The name server was  unable to interpret the query.
	SERVERERR = 2 #Server failure - The name server was unable to process this query due to a problem with the name server.
	NAMEERR = 3 #Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	NOTIMPL = 4 #Not Implemented - The name server does not support the requested kind of query.
	REFUSED = 5 #Refused - The name server refuses to perform the specified operation for policy reasons.
	RESERVED6 = 6
	RESERVED7 = 7
	RESERVED8 = 8
	RESERVED9 = 9
	RESERVED10 = 10
	RESERVED11 = 11
	RESERVED12 = 12
	RESERVED13 = 13
	RESERVED14 = 14
	RESERVED15 = 15

class DNSType(enum.Enum):
	A     = 1 #a host address (IPv4)
	NS    = 2 #an authoritative name server
	MD    = 3 #a mail destination (Obsolete - use MX)
	MF    = 4 #a mail forwarder (Obsolete - use MX)
	CNAME = 5 #the canonical name for an alias
	SOA   = 6 #marks the start of a zone of authority
	MB    = 7 #a mailbox domain name (EXPERIMENTAL)
	MG    = 8 #a mail group member (EXPERIMENTAL)
	MR    = 9 #a mail rename domain name (EXPERIMENTAL)
	NULL  = 10 #a null RR (EXPERIMENTAL)
	WKS   = 11 #a well known service description
	PTR   = 12 #a domain name pointer
	HINFO = 13 #host information
	MINFO = 14 #mailbox or mail list information
	MX    = 15 #mail exchange
	TXT   = 16 #text strings
	AAAA  = 28 #a host address (IPv4)
	ANY   = 255 #EVERYTHING

class DNSClass(enum.Enum):
	IN = 1 #the Internet
	CS = 2 #the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CH = 3 #the CHAOS class
	HS = 4 #Hesiod [Dyer 87]
	ANY = 255



class DNSQuestion():
	def __init__(self, data = None):
		self.QNAME_LEN = None
		self.QNAME = None
		self.QTYPE = None
		self.QCLASS = None

		if data is not None:
			self.parse(data)

	def parse(self, data):
		#data is io.byteio!!!!!
		self.QNAME_LEN = data.read(1)[0]
		self.QNAME = ''
		if self.QNAME_LEN == 32:
			self.decode_NS(data.read(self.QNAME_LEN))
			data.read(1)
		else:
			self.QNAME  = data.read(self.QNAME_LEN).decode()
			data.read(1)
		self.QTYPE  = DNSType(int.from_bytes(data.read(2), byteorder = 'big'))
		self.QCLASS = DNSClass(int.from_bytes(data.read(2), byteorder = 'big'))

	def toBytes(self):
		t  = self.QNAME_LEN.to_bytes(1, byteorder = 'big')
		t += self.QNAME.encode() + b'\x00'
		t += self.QTYPE.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.QCLASS.value.to_bytes(2, byteorder = 'big', signed = False)

		return t

	def construct(self, qname, qtype, qclass):
		self.QNAME_LEN = len(qname.encode()) + 1 #ending zero!
		self.QNAME     = qname
		self.QTYPE     = qtype
		self.QCLASS    = qclass

	def decode_NS(self, encoded_name):
		#encoded http://www.ietf.org/rfc/rfc1001.txt
		transform = [((i - 0x41)& 0x0F) for i in encoded_name]
		i = 0
		while i < len(transform):
			self.QNAME += chr(transform[i] << 4 | transform[i+1] ) 
			i+=2

	def __repr__(self):
		t = '== DNSQuestion ==\r\n'
		t+= 'QNAME:  %s\r\n' % self.QNAME
		t+= 'QTYPE:  %s\r\n' % self.QTYPE.name
		t+= 'QCLASS: %s\r\n' % self.QCLASS.name
		return t

class DNSResource():
	def __init__(self, data = None):
		self.NAME_LEN = None
		self.NAME     = None
		self.TYPE     = None
		self.CLASS    = None
		self.TTL      = None
		self.RDLENGTH = None
		self.RDATA    = None


		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.NAME_LEN = data.read(1)[0]
		self.NAME     = data.read(self.NAME_LEN).decode()
		self.TYPE     = DNSType(int.from_bytes(data.read(2), byteorder = 'big'))
		self.CLASS    = DNSClass(int.from_bytes(data.read(2), byteorder = 'big'))
		self.TTL      = int.from_bytes(data.read(4), byteorder = 'big')
		self.RDLENGTH = int.from_bytes(data.read(2), byteorder = 'big')
		trdata        = data.read(self.RDLENGTH)

		if self.TYPE in [DNSType.A, DNSType.ANY] and self.CLASS == DNSClass.IN:
			self.RDATA = ipaddress.IPv4Address(trdata)

		#TODO for other types :)
		else:
			self.RDATA = trdata

	
	def toBytes(self):
		t  = self.NAME_LEN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.NAME
		t += self.TYPE.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.CLASS.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.TTL.to_bytes(4, byteorder = 'big', signed = False)
		t += self.RDLENGTH.to_bytes(2, byteorder = 'big', signed = False)
		t += self.RDATA

		return t

	def construct(self, rname, rtype, rdata, ttl = 3000, rclass = DNSClass.IN):
		self.NAME     = rname.encode() + b'\x00'
		self.NAME_LEN = len(self.NAME) - 1
		self.TYPE     = rtype
		self.CLASS    = rclass
		self.TTL      = ttl

		if self.TYPE  == DNSType.A and self.CLASS == DNSClass.IN:
			self.RDATA = rdata.packed

		self.RDLENGTH = len(self.RDATA)
	
	def __repr__(self):
		t = '== DNSResource ==\r\n'
		t+= 'NAME:  %s\r\n' % self.NAME
		t+= 'TYPE:  %s\r\n' % self.TYPE.name
		t+= 'CLASS: %s\r\n' % self.CLASS.name
		t+= 'TTL: %s\r\n' % self.TTL
		t+= 'RDLENGTH: %s\r\n' % self.RDLENGTH
		t+= 'RDATA: %s\r\n' % repr(self.RDATA)
		return t