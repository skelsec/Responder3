#https://tools.ietf.org/html/rfc2131
#https://tools.ietf.org/html/rfc1533
import io
import enum
import asyncio
import ipaddress

class DHCPOpcode(enum.Enum):
	BOOTREQUEST = 1
	BOOTREPLY   = 2

class DHCPFlags(enum.IntFlag):
	B = 0x8000

#https://tools.ietf.org/html/rfc1700
class DHCPHardwareType(enum.Enum):
	STRING = 0 #not in RFC, but from packet dissection it seems like this type indicates a string
	ETHERNET_10MB                        =  1  
	EXPERIMENTAL_ETHERNET_3MB            =  2  
	AMATEUR_RADIO_AX25                    =  3  
	PROTEON_PRONET_TOKEN_RING              =  4  
	CHAOS                                  =  5  
	IEEE_802_NETWORKS                      =  6  
	ARCNET                                 =  7  
	HYPERCHANNEL                           =  8  
	LANSTAR                                =  9  
	AUTONET_SHORT_ADDRESS                  = 10  
	LOCALTALK                              = 11  
	LOCALNET                          = 12  
	ULTRA_LINK                             = 13  
	SMDS                                   = 14  
	FRAME_RELAY                            = 15  
	ASYNCHRONOUS_TRANSMISSION_MODE_16 = 16  
	HDLC                           = 17  
	FIBRE_CHANNEL                  = 18  
	ASYNCHRONOUS_TRANSMISSION_MODE_19 = 19  
	SERIAL_LINE                    = 20  
	ASYNCHRONOUS_TRANSMISSION_MODE_21 = 21 

def bytes_to_mac(b):
	return ':'.join([b.hex()[i:i+2] for i in range(0, len(b.hex()), 2)])

def mac_to_bytes(m):
	return bytes.fromhex(m.replace(':','').strip())

class DHCPMessage():
	def __init__(self):
		self.op = None
		self.htype = None #Hardware address type
		self.hlen  = None #Hardware address length
		self.hops  = None #Client sets to zero, optionally used by relay agents when booting via a relay agent.
		self.xid   = None #Transaction ID
		self.secs  = None #seconds elapsed since client began address acquisition or renewal process.
		self.flags = None #flags
		self.ciaddr = None #Client IP address
		self.yiaddr = None #'your' (client) IP address.
		self.siaddr = None #IP address of next server to use in bootstrap
		self.giaddr = None #Relay agent IP address
		self.chaddr = None #Client hardware address.
		self.chaddr_padding = None
		self.sname = None #Optional server host name, null terminated string.
		self.file = None #Boot file name, null terminated string;
		self.magic = None #Queen
		self.options = None
		self.padding = None

		#helper variables, not part of the standard
		self.dhcpmessagetype = None

	async def from_streamreader(reader):
		#running on UDP with no fragmentation possible, we just read everything from buffer and parse it
		return DHCPMessage.from_buffer(reader.buff)

	def from_bytes(bbuff):
		return DHCPMessage.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		msg = DHCPMessage()
		msg.op      = DHCPOpcode(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		msg.htype   = DHCPHardwareType(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		msg.hlen    = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		msg.hops    = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		msg.xid     = buff.read(4)
		msg.secs    = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
		msg.flags   = DHCPFlags(int.from_bytes(buff.read(2), byteorder = 'big', signed=False))
		msg.ciaddr  = ipaddress.ip_address(buff.read(4))
		msg.yiaddr  = ipaddress.ip_address(buff.read(4))
		msg.siaddr  = ipaddress.ip_address(buff.read(4))
		msg.giaddr  = ipaddress.ip_address(buff.read(4))
		msg.chaddr  = bytes_to_mac(buff.read(msg.hlen))
		msg.chaddr_padding = buff.read(16-msg.hlen)
		msg.sname   = buff.read(64).decode().strip() #null-terminated
		msg.file    = buff.read(128).decode().strip() #null-terminated
		msg.magic   = buff.read(4)
		msg.options = DHCPOptionsParser.from_buffer(buff)
		msg.padding = buff.read()

		for option in msg.options:
			if option.code == 53:
				msg.dhcpmessagetype = option.msgtype

		return msg

	def construct(tid, opcode, options, hwtype = DHCPHardwareType.ETHERNET_10MB, 
					macaddress = 'AA:AA:AA:AA:AA:AA', hops = 0, secs = 0, 
					flags = DHCPFlags.B,
					giaddr = ipaddress.ip_address('0.0.0.0'), 
					ciaddr=ipaddress.ip_address('0.0.0.0'), 
					yiaddr=ipaddress.ip_address('0.0.0.0'), 
					siaddr=ipaddress.ip_address('0.0.0.0'),
					sname = '', file=''):
		msg = DHCPMessage()
		msg.op      = opcode
		msg.htype   = hwtype
		msg.chaddr  = macaddress
		msg.hlen    = len(mac_to_bytes(macaddress))
		msg.hops    = hops
		msg.xid     = tid
		msg.secs    = secs
		msg.flags   = flags
		msg.ciaddr  = ciaddr
		msg.yiaddr  = yiaddr
		msg.siaddr  = siaddr
		msg.giaddr  = giaddr
		msg.sname   = sname
		msg.file    = file
		msg.magic   = b'\x63\x82\x53\x63'
		msg.options = options
		return msg

	def to_bytes(self):
		t  = self.op.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.htype.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.hlen.to_bytes(1, byteorder = 'big', signed = False)
		t += self.hops.to_bytes(1, byteorder = 'big', signed = False)
		t += self.xid
		t += self.secs.to_bytes(2, byteorder = 'big', signed = False)
		t += self.flags.to_bytes(2, byteorder = 'big', signed = False)
		t += self.ciaddr.packed
		t += self.yiaddr.packed 
		t += self.siaddr.packed 
		t += self.giaddr.packed 
		t += mac_to_bytes(self.chaddr) + b'\x00'*(16-self.hlen)
		t += self.sname.encode() + b'\x00'*(64-len(self.sname.encode()))
		t += self.file.encode() + b'\x00'*(128-len(self.file.encode()))
		t += self.magic
		for option in self.options:
			t += option.to_bytes()
		
		t += b'\x00'*(576 - len(t))

		return t

	def __repr__(self):
		t  = '== DHCPMessage ==\r\n'
		t += 'op : %s\r\n' % self.op
		t += 'htype : %s\r\n' % self.htype
		t += 'hlen : %s\r\n' % self.hlen
		t += 'hops : %s\r\n' % self.hops
		t += 'xid : %s\r\n' % repr(self.xid)
		t += 'secs : %s\r\n' % self.secs
		t += 'flags : %s\r\n' % repr(self.flags.name)
		t += 'ciaddr : %s\r\n' % self.ciaddr
		t += 'yiaddr : %s\r\n' % self.yiaddr
		t += 'siaddr : %s\r\n' % self.siaddr
		t += 'giaddr : %s\r\n' % self.giaddr
		t += 'chaddr : %s\r\n' % self.chaddr
		t += 'chaddr_padding : %s\r\n' % self.chaddr_padding
		t += 'sname : %s\r\n' % self.sname
		t += 'file : %s\r\n' % self.file
		t += 'magic : %s\r\n' % self.magic
		for option in self.options:
			t += repr(option)

		return t

class DHCPOptPAD():
	def __init__(self):
		self.code = 0

	def from_buffer(buff):
		opt = DHCPOptPAD()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		return opt
	def construct():
		opt = DHCPOptPAD()
		return opt
	def to_bytes(self):
		return self.code.to_bytes(1, byteorder = 'big', signed = False)

	def __repr__(self):
		t = '= PAD =\r\n'
		return t

class DHCPOptEND():
	def __init__(self):
		self.code = 255

	def from_buffer(buff):
		opt = DHCPOptEND()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		return opt

	def construct():
		opt = DHCPOptEND()
		return opt

	def to_bytes(self):
		return self.code.to_bytes(1, byteorder = 'big', signed = False)

	def __repr__(self):
		t = '= END =\r\n'
		return t

class DHCPOptSUBNETMASK():
	def __init__(self):
		self.code = 1
		self.len  = 4
		self.mask = None

	def from_buffer(buff):
		opt = DHCPOptSUBNETMASK()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.mask = bytes_to_mac(buff.read(opt.len))
		return opt

	def construct(mask):
		opt = DHCPOptSUBNETMASK()
		opt.mask = mask
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += mac_to_bytes(self.mask)
		return t

	def __repr__(self):
		t  = '= SUBNETMASK =\r\n'
		t += 'NetMask: %s\r\n' % self.mask
		return t

class DHCPOptTIMEOFFSET():
	def __init__(self):
		self.code = 2
		self.len  = 4
		self.timeoffset = None
	
	def from_buffer(buff):
		opt = DHCPOptTIMEOFFSET()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.timeoffset = int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=True)
		return opt

	def construct(timeoffset):
		opt = DHCPOptTIMEOFFSET()
		opt.timeoffset = timeoffset
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.timeoffset.to_bytes(4,byteorder = 'big', signed=True)
		return t

	def __repr__(self):
		t  = '= TIMEOFFSET =\r\n'
		t += 'timeoffset: %s\r\n' % self.timeoffset
		return t

class DHCPOptROUTERS():
	def __init__(self):
		self.code = 3
		self.len  = None
		self.addresses = []
	
	def from_buffer(buff):
		opt = DHCPOptROUTERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptROUTERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= ROUTERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptTIMESERVERS():
	def __init__(self):
		self.code = 4
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptTIMESERVERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptTIMESERVERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= TIMESERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptNAMESERVERS():
	def __init__(self):
		self.code = 5
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptNAMESERVERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptNAMESERVERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= NAMESERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptDNSSERVERS():
	def __init__(self):
		self.code = 6
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptDNSSERVERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptDNSSERVERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def from_setting(setting):
		opt = DHCPOptDNSSERVERS()
		addresses = setting
		if not isinstance(setting, list):
			addresses = [setting]
		for address in addresses:
			opt.addresses.append(ipaddress.ip_address(address))
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= DNSSERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t


class DHCPOptLOGSERVERS():
	def __init__(self):
		self.code = 7
		self.len  = None
		self.addresses = []
	
	def from_buffer(buff):
		opt = DHCPOptLOGSERVERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptLOGSERVERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= LOGSERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptCOOKIESERVER():
	def __init__(self):
		self.code = 8
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptCOOKIESERVER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptCOOKIESERVER()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= COOKIESERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptLPRSERVERS():
	def __init__(self):
		self.code = 9
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptLPRSERVERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptLPRSERVERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= LPRSERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptIMPRESSSERVERS():
	def __init__(self):
		self.code = 10
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptIMPRESSSERVERS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptIMPRESSSERVERS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= IMPRESSSERVERS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptRESOURCELOCATIONS():
	def __init__(self):
		self.code = 11
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptRESOURCELOCATIONS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptRESOURCELOCATIONS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= RESOURCELOCATIONS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptHOSTNAME():
	def __init__(self):
		self.code = 12
		self.len  = None
		self.hostname = None

	def from_buffer(buff):
		opt = DHCPOptHOSTNAME()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.hostname = buff.read(opt.len).decode()
		return opt

	def construct(hostname):
		opt = DHCPOptHOSTNAME()
		opt.hostname = hostname
		opt.len = len(hostname.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.hostname.encode()
		return t

	def __repr__(self):
		t  = '= HOSTNAME =\r\n'
		t += 'hostname: %s\r\n' % str(self.hostname)
		return t

class DHCPOptBOOTFILESIZE():
	def __init__(self):
		self.code = 13
		self.len  = 2
		self.filesize = None

	def from_buffer(buff):
		opt = DHCPOptBOOTFILESIZE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.filesize = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
		return opt

	def construct(filesize):
		opt = DHCPOptBOOTFILESIZE()
		opt.filesize = filesize
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.filesize.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= BOOTFILESIZE =\r\n'
		t += 'filesize: %s\r\n' % str(self.filesize)
		return t


class DHCPOptMERITDUMPFILE():
	def __init__(self):
		self.code = 14
		self.len  = None
		self.pathname = None

	def from_buffer(buff):
		opt = DHCPOptMERITDUMPFILE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.pathname = buff.read(opt.len).decode()
		return opt

	def construct(pathname):
		opt = DHCPOptMERITDUMPFILE()
		opt.pathname = pathname
		opt.len = len(pathname.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.pathname.encode()
		return t

	def __repr__(self):
		t  = '= MERITDUMPFILE =\r\n'
		t += 'pathname: %s\r\n' % str(self.pathname)
		return t


class DHCPOptDOMAINNAME():
	def __init__(self):
		self.code = 15
		self.len  = None
		self.domainname = None

	def from_buffer(buff):
		opt = DHCPOptDOMAINNAME()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.domainname = buff.read(opt.len).decode()
		return opt

	def construct(domainname):
		opt = DHCPOptDOMAINNAME()
		opt.domainname = domainname
		opt.len = len(domainname.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.domainname.encode()
		return t

	def __repr__(self):
		t  = '= DOMAINNAME =\r\n'
		t += 'domainname: %s\r\n' % str(self.domainname)
		return t

class DHCPOptSWAPSERVER():
	def __init__(self):
		self.code = 16
		self.len  = 4
		self.address = None

	def from_buffer(buff):
		opt = DHCPOptSWAPSERVER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.address = ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
		return opt

	def construct(address):
		opt = DHCPOptSWAPSERVER()
		opt.address = address
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.address.packed
		return t

	def __repr__(self):
		t  = '= SWAPSERVER =\r\n'
		t += 'address: %s\r\n' % str(self.address)
		return t

class DHCPOptROOTPATH():
	def __init__(self):
		self.code = 17
		self.len  = None
		self.pathname = None

	def from_buffer(buff):
		opt = DHCPOptROOTPATH()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.pathname = buff.read(opt.len).decode()
		return opt

	def construct(pathname):
		opt = DHCPOptROOTPATH()
		opt.pathname = pathname
		opt.len = len(pathname.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.pathname.encode()
		return t

	def __repr__(self):
		t  = '= ROOTPATH =\r\n'
		t += 'pathname: %s\r\n' % str(self.pathname)
		return t

class DHCPOptEXTENSIONSPATH():
	def __init__(self):
		self.code = 18
		self.len  = None
		self.pathname = None

	def from_buffer(buff):
		opt = DHCPOptEXTENSIONSPATH()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.pathname = buff.read(opt.len).decode()
		return opt

	def construct(pathname):
		opt = DHCPOptEXTENSIONSPATH()
		opt.pathname = pathname
		opt.len = len(pathname.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.pathname.encode()
		return t

	def __repr__(self):
		t  = '= EXTENSIONSPATH =\r\n'
		t += 'pathname: %s\r\n' % str(self.pathname)
		return t

class DHCPOptIPFORWARDING():
	def __init__(self):
		self.code = 19
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptIPFORWARDING()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptIPFORWARDING()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= IPFORWARDING =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptNONLOCALSRCROUTING():
	def __init__(self):
		self.code = 20
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptNONLOCALSRCROUTING()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptNONLOCALSRCROUTING()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= NONLOCALSRCROUTING =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptPOLICYFILTER():
	def __init__(self):
		self.code = 21
		self.len  = None
		self.destmasks = [] #should be a list of tuples

	def from_buffer(buff):
		opt = DHCPOptPOLICYFILTER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/8)):
			ip = ipaddress.ip_addres(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
			mask = bytes_to_mac(buff.read(4))
			opt.destmasks.append((ip,mask))
		
		return opt

	def construct(destmasks):
		opt = DHCPOptPOLICYFILTER()
		if not isinsance(destmasks,list):
			destmasks = [destmasks]
		opt.destmasks = destmasks
		opt.len = len(destmasks)*8

		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for destmask in destmasks:
			t += destmask[0].packed + mac_to_bytes(destmask[1])
		return t

	def __repr__(self):
		t  = '= POLICYFILTER =\r\n'
		for addr, mask in self.destmasks:
			t += 'addr: %s mask:%s\r\n' % (str(addr), mask)
		return t

class DHCPOptMAXIMUMDATAGRAMREASSEMBLY():
	def __init__(self):
		self.code = 22
		self.len  = 2
		self.size = None

	def from_buffer(buff):
		opt = DHCPOptMAXIMUMDATAGRAMREASSEMBLY()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.size = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
		return opt

	def construct(size):
		opt = DHCPOptMAXIMUMDATAGRAMREASSEMBLY()
		opt.size = size
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.size.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= MAXIMUMDATAGRAMREASSEMBLY =\r\n'
		t += 'size: %s\r\n' % str(self.size)
		return t

class DHCPOptDEFAULTTTL():
	def __init__(self):
		self.code = 23
		self.len  = 1
		self.ttl  = None

	def from_buffer(buff):
		opt = DHCPOptDEFAULTTTL()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.ttl = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		return opt

	def construct(ttl):
		opt = DHCPOptDEFAULTTTL()
		opt.ttl = ttl
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ttl.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= DEFAULTTTL =\r\n'
		t += 'ttl: %s\r\n' % str(self.ttl)
		return t

class DHCPOptPATHMTUAGINGTIMEOUT():
	def __init__(self):
		self.code = 24
		self.len  = 4
		self.timeout  = None

	def from_buffer(buff):
		opt = DHCPOptPATHMTUAGINGTIMEOUT()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.timeout = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(ttl):
		opt = DHCPOptPATHMTUAGINGTIMEOUT()
		opt.timeout = timeout
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.timeout.to_bytes(4, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= PATHMTUAGINGTIMEOUT =\r\n'
		t += 'timeout: %s\r\n' % str(self.timeout)
		return t

class DHCPOptMTUPLATEUTABLE():
	def __init__(self):
		self.code = 25
		self.len  = None
		self.sizes= [] #list of sizes (of 2byte integers)

	def from_buffer(buff):
		opt = DHCPOptMTUPLATEUTABLE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(opt.len/2):
			opt.sizes.append(int.from_bytes(buff.read(2), byteorder = 'big', signed=False))
		return opt

	def construct(sizes):
		opt = DHCPOptMTUPLATEUTABLE()
		opt.sizes = sizes
		opt.len = len(sizes) * 2
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for size in sizes:
			t += size.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= MTUPLATEUTABLE =\r\n'
		t += 'sizes: %s\r\n' % str(self.sizes)
		return t

class DHCPOptINTERFACEMTU():
	def __init__(self):
		self.code = 26
		self.len  = 2
		self.mtu  = None

	def from_buffer(buff):
		opt = DHCPOptINTERFACEMTU()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.mtu = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
		return opt

	def construct(mtu):
		opt = DHCPOptINTERFACEMTU()
		opt.mtu = mtu
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.mtu.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= INTERFACEMTU =\r\n'
		t += 'mtu: %s\r\n' % str(self.mtu)
		return t

class DHCPOptALLSUBNETSARELOCAL():
	def __init__(self):
		self.code = 27
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptALLSUBNETSARELOCAL()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptALLSUBNETSARELOCAL()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= ALLSUBNETSARELOCAL =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t


class DHCPOptBROADCASTADDRESS():
	def __init__(self):
		self.code = 28
		self.len  = 4
		self.address = None

	def from_buffer(buff):
		opt = DHCPOptBROADCASTADDRESS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.address = ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
		return opt

	def construct(address):
		opt = DHCPOptBROADCASTADDRESS()
		opt.address = address
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.address.packed
		return t

	def __repr__(self):
		t  = '= BROADCASTADDRESS =\r\n'
		t += 'address: %s\r\n' % str(self.address)
		return t

class DHCPOptPERFORMMASKDISCOVERY():
	def __init__(self):
		self.code = 29
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptPERFORMMASKDISCOVERY()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptPERFORMMASKDISCOVERY()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= PERFORMMASKDISCOVERY =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptMASKSUPPLIER():
	def __init__(self):
		self.code = 30
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptMASKSUPPLIER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptMASKSUPPLIER()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= MASKSUPPLIER =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t


class DHCPOptPERFORMROUTERDISCOVERY():
	def __init__(self):
		self.code = 31
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptPERFORMROUTERDISCOVERY()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptPERFORMROUTERDISCOVERY()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t
	
	def __repr__(self):
		t  = '= PERFORMROUTERDISCOVERY =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptROUTERSOLICITATIONADDRESS():
	def __init__(self):
		self.code = 32
		self.len  = 4
		self.address = None

	def from_buffer(buff):
		opt = DHCPOptROUTERSOLICITATIONADDRESS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.address = ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
		return opt

	def construct(address):
		opt = DHCPOptROUTERSOLICITATIONADDRESS()
		opt.address = address
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.address.packed
		return t

	def __repr__(self):
		t  = '= ROUTERSOLICITATIONADDRESS =\r\n'
		t += 'address: %s\r\n' % str(self.address)
		return t

class DHCPOptSTATICROUTES():
	def __init__(self):
		self.code = 33
		self.len  = None
		self.addressroutes = []

	def from_buffer(buff):
		opt = DHCPOptSTATICROUTES()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/8)):
			ip = ipaddress.ip_addres(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
			route = ipaddress.ip_addres(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
			opt.addressroutes.append((ip,route))
		
		return opt

	def construct(addressroutes):
		opt = DHCPOptSTATICROUTES()
		if not isinsance(addressroutes,list):
			addressroutes = [addressroutes]
		opt.addressroutes = addressroutes
		opt.len = len(addressroutes) * 8

		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for addressroutes in self.addressroutes:
			t += addressroute[0].packed + addressroute[1].packed
		return t

	def __repr__(self):
		t  = '= STATICROUTES =\r\n'
		for addr, route in self.addressroutes:
			t += 'addr: %s route: %s \r\n' % (str(addr),str(route))
		return t

class DHCPOptTRAILERENCAPSULATION():
	def __init__(self):
		self.code = 34
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptTRAILERENCAPSULATION()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptTRAILERENCAPSULATION()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= TRAILERENCAPSULATION =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptARPCACHETIMEOUT():
	def __init__(self):
		self.code = 35
		self.len  = 4
		self.timeout = None

	def from_buffer(buff):
		opt = DHCPOptARPCACHETIMEOUT()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.ttl = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(ttl):
		opt = DHCPOptARPCACHETIMEOUT()
		opt.timeout = timeout
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.timeout.to_bytes(4, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= ARPCACHETIMEOUT =\r\n'
		t += 'timeout: %s\r\n' % str(self.timeout)
		return t

class DHCPOptETHERNETENCAPSULATION():
	def __init__(self):
		self.code = 36
		self.len  = 1
		self.enabled = None

	def from_buffer(buff):
		opt = DHCPOptETHERNETENCAPSULATION()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptETHERNETENCAPSULATION()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= ETHERNETENCAPSULATION =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptTCPDEFAULTTTL():
	def __init__(self):
		self.code = 37
		self.len  = 1
		self.ttl = None
	
	def from_buffer(buff):
		opt = DHCPOptTCPDEFAULTTTL()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.ttl = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(ttl):
		opt = DHCPOptTCPDEFAULTTTL()
		opt.timeout = timeout
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.timeout.to_bytes(4, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= TCPDEFAULTTTL =\r\n'
		t += 'ttl: %s\r\n' % str(self.ttl)
		return t

class DHCPOptTCPKEEPALIVEINTERVAL():
	def __init__(self):
		self.code = 38
		self.len  = 4
		self.timeout = None 

	def from_buffer(buff):
		opt = DHCPOptTCPKEEPALIVEINTERVAL()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.ttl = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(ttl):
		opt = DHCPOptTCPKEEPALIVEINTERVAL()
		opt.timeout = timeout
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.timeout.to_bytes(4, byteorder = 'big', signed = False)
		return t
	
	def __repr__(self):
		t  = '= TCPKEEPALIVEINTERVAL =\r\n'
		t += 'timeout: %s\r\n' % str(self.timeout)
		return t

class DHCPOptTCPKEEPALIVEGARBAGE():
	def __init__(self):
		self.code = 39
		self.len  = 1
		self.enabled  = None

	def from_buffer(buff):
		opt = DHCPOptTCPKEEPALIVEGARBAGE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.enabled = bool(int.from_bytes(buff.read(opt.len), byteorder = 'big', signed=False))
		return opt

	def construct(enabled):
		opt = DHCPOptTCPKEEPALIVEGARBAGE()
		opt.enabled = enabled
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.enabled.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= TCPKEEPALIVEGARBAGE =\r\n'
		t += 'enabled: %s\r\n' % str(self.enabled)
		return t

class DHCPOptNISDOMAIN():
	def __init__(self):
		self.code = 40
		self.len  = None
		self.domainname = None

	def from_buffer(buff):
		opt = DHCPOptNISDOMAIN()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.domainname = buff.read(opt.len).decode()
		return opt

	def construct(domainname):
		opt = DHCPOptNISDOMAIN()
		opt.domainname = domainname
		opt.len = len(domainname.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.domainname.encode()
		return t
	
	def __repr__(self):
		t  = '= NISDOMAIN =\r\n'
		t += 'domainname: %s\r\n' % str(self.domainname)
		return t

class DHCPOptNIS():
	def __init__(self):
		self.code = 41
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptNIS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptNIS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= NIS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptNTP():
	def __init__(self):
		self.code = 42
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptNTP()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def from_setting(setting):
		opt = DHCPOptNTP()
		addresses = setting
		if not isinstance(setting, list):
			addresses = [setting]
		for address in addresses:
			opt.addresses.append(ipaddress.ip_address(address))
		opt.len = len(addresses) *4
		return opt

	def construct(addresses):
		opt = DHCPOptNTP()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= NTP =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptVENDORSPECIFIC():
	def __init__(self):
		self.code = 43
		self.len  = None
		self.data = None

	def from_buffer(buff):
		opt = DHCPOptVENDORSPECIFIC()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.data = buff.read(opt.len)
		return opt

	def __repr__(self):
		t  = '= VENDORSPECIFIC =\r\n'
		t += 'code: %s\r\n' % str(self.code)
		t += 'len: %s\r\n' % str(self.len)
		t += 'data: %s\r\n' % str(self.data.hex())
		return t

class DHCPOptNETBIOSOVERTCP():
	def __init__(self):
		self.code = 44
		self.len  = None
		self.addresses = []
	
	def from_buffer(buff):
		opt = DHCPOptNETBIOSOVERTCP()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptNETBIOSOVERTCP()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t
	def __repr__(self):
		t  = '= NETBIOSOVERTCP =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptNETBIOSOVERTCPDDS():
	def __init__(self):
		self.code = 45
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptNETBIOSOVERTCPDDS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptNETBIOSOVERTCPDDS()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= NETBIOSOVERTCPDDS =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DNSOptNetBIOSNodeType(enum.Enum):
	B_NODE = 1
	P_NODE = 2
	M_NODE = 4
	H_NODE = 8

class DHCPOptNETBIOSOVERTCPNODETYPE():
	def __init__(self):
		self.code = 46
		self.len  = 1
		self.nodetype = None
	
	def from_buffer(buff):
		opt = DHCPOptNETBIOSOVERTCPNODETYPE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.nodetype = DNSOptNetBIOSNodeType(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		return opt

	def construct(nodetype):
		opt = DHCPOptNETBIOSOVERTCPNODETYPE()
		if not isinstance(nodetype, DNSOptNetBIOSNodeType):
			nodetype = DNSOptNetBIOSNodeType[nodetype]
		opt.nodetype = nodetype
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.nodetype.value.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= NETBIOSOVERTCPNODETYPE =\r\n'
		t += 'nodetype: %s\r\n' % str(self.nodetype)
		return t

class DHCPOptNETBIOSOVERTCPSCOPE():
	#TODO
	def __init__(self):
		self.code = 47
		self.len  = None
		self.scope = None

	def from_buffer(buff):
		opt = DHCPOptNETBIOSOVERTCPSCOPE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.scope = buff.read(opt.len)
		return opt

	def construct(scope):
		opt = DHCPOptNETBIOSOVERTCPSCOPE()
		opt.scope = scope
		opt.len = len(scope)
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.scope
		return t

	def __repr__(self):
		t  = '= NETBIOSOVERTCPSCOPE =\r\n'
		t += 'scope: %s\r\n' % str(self.scope)
		return t

class DHCPOptXWINDOWFONTSERVER():
	def __init__(self):
		self.code = 48
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptXWINDOWFONTSERVER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptXWINDOWFONTSERVER()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= XWINDOWFONTSERVER =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptXWINDOWDISPLAYMANAGER():
	def __init__(self):
		self.code = 49
		self.len  = None
		self.addresses = []

	def from_buffer(buff):
		opt = DHCPOptXWINDOWDISPLAYMANAGER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(int(opt.len/4)):
			opt.addresses.append(ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False)))
		return opt

	def construct(addresses):
		opt = DHCPOptXWINDOWDISPLAYMANAGER()
		if not isinstance(addresses, list):
			addresses = [addresses]
		opt.addresses = addresses
		opt.len = len(addresses) *4
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for address in self.addresses:
			t += address.packed
		return t

	def __repr__(self):
		t  = '= XWINDOWDISPLAYMANAGER =\r\n'
		for addr in self.addresses:
			t += 'addr: %s\r\n' % str(addr)
		return t

class DHCPOptREQUESTEDIPADDRESS():
	def __init__(self):
		self.code = 50
		self.len  = 4
		self.address = None

	def from_buffer(buff):
		opt = DHCPOptREQUESTEDIPADDRESS()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.address = ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
		return opt

	def construct(address):
		opt = DHCPOptREQUESTEDIPADDRESS()
		opt.address = address
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.address.packed
		return t

	def __repr__(self):
		t  = '= REQUESTEDIPADDRESS =\r\n'
		t += 'address: %s\r\n' % str(self.address)
		return t

class DHCPOptIPADDRESSLEASETIME():
	def __init__(self):
		self.code = 51
		self.len  = 4
		self.leasetime = None


	def from_buffer(buff):
		opt = DHCPOptIPADDRESSLEASETIME()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.leasetime = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(leasetime):
		opt = DHCPOptIPADDRESSLEASETIME()
		opt.leasetime = leasetime
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.leasetime.to_bytes(4, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= IPADDRESSLEASETIME =\r\n'
		t += 'leasetime: %s\r\n' % str(self.leasetime)
		return t

class DNSOptOptionOverLoadType(enum.Enum):
	FILE = 1
	SNAME = 2
	BOTH = 3

class DHCPOptOPTIONOVERLOAD():
	def __init__(self):
		self.code = 52
		self.len  = 1
		self.value = None

	def from_buffer(buff):
		opt = DHCPOptOPTIONOVERLOAD()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.value = DNSOptOptionOverLoadType(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		return opt

	def construct(value):
		opt = DHCPOptOPTIONOVERLOAD()
		opt.value = value
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.value.value.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= OPTIONOVERLOAD =\r\n'
		t += 'value: %s\r\n' % str(self.value)
		return t


class DHCPOptMessageType(enum.Enum):
	DHCPDISCOVER = 1
	DHCPOFFER    = 2
	DHCPREQUEST  = 3
	DHCPDECLINE  = 4
	DHCPACK      = 5
	DHCPNAK      = 6
	DHCPRELEASE  = 7
	DHCPINFORM   = 8


class DHCPOptDHCPMESSAGETYPE():
	def __init__(self):
		self.code = 53
		self.len  = 1
		self.msgtype = None

	def from_buffer(buff):
		opt = DHCPOptDHCPMESSAGETYPE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.msgtype = DHCPOptMessageType(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		return opt

	def construct(msgtype):
		opt = DHCPOptDHCPMESSAGETYPE()
		opt.msgtype = msgtype
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.msgtype.value.to_bytes(1, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= DHCPMESSAGETYPE =\r\n'
		t += 'msgtype: %s\r\n' % str(self.msgtype)
		return t

class DHCPOptSERVERIDENTIFIER():
	def __init__(self):
		self.code = 54
		self.len  = 4
		self.address = None
	
	def from_buffer(buff):
		opt = DHCPOptSERVERIDENTIFIER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.address = ipaddress.ip_address(int.from_bytes(buff.read(4), byteorder = 'big', signed=False))
		return opt

	def construct(address):
		opt = DHCPOptSERVERIDENTIFIER()
		opt.address = address
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.address.packed
		return t

	def __repr__(self):
		t  = '= DHCPMESSAGETYPE =\r\n'
		t += 'address: %s\r\n' % str(self.address)
		return t


class DHCPOptPARAMETERREQUEST():
	def __init__(self):
		self.code = 55
		self.len  = None
		self.optioncodes = []

	def from_buffer(buff):
		opt = DHCPOptPARAMETERREQUEST()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		for i in range(opt.len):
			opt.optioncodes.append(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		return opt

	def construct(optioncodes):
		opt = DHCPOptPARAMETERREQUEST()
		opt.optioncodes = optioncodes
		opt.len = len(optioncodes)
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		for optioncode in self.optioncodes:
			t+= optioncode.to_bytes(1, byteorder = 'big', signed = False)
		return t
	
	def __repr__(self):
		t  = '= PARAMETERREQUEST =\r\n'
		t += 'optioncodes: %s\r\n' % str(self.optioncodes)
		return t

class DHCPOptMESSAGE():
	def __init__(self):
		self.code = 56
		self.len  = None
		self.message = None

	def from_buffer(buff):
		opt = DHCPOptMESSAGE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.message = buff.read(opt.len).decode()
		return opt

	def construct(message):
		opt = DHCPOptMESSAGE()
		opt.message = message
		opt.len = len(message.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.message.encode()
		return t

	def __repr__(self):
		t  = '= MESSAGE =\r\n'
		t += 'message: %s\r\n' % str(self.message)
		return t

class DHCPOptMAXIMUMDHCPMESSAGESIZE():
	def __init__(self):
		self.code = 57
		self.len  = 2
		self.length = None

	def from_buffer(buff):
		opt = DHCPOptMAXIMUMDHCPMESSAGESIZE()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.length = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
		return opt

	def construct(length):
		opt = DHCPOptMAXIMUMDHCPMESSAGESIZE()
		opt.length = length
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.length.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= MAXIMUMDHCPMESSAGESIZE =\r\n'
		t += 'length: %s\r\n' % str(self.length)
		return t

class DHCPOptRENEVALTIME():
	def __init__(self):
		self.code = 58
		self.len  = 4
		self.interval = None

	def from_buffer(buff):
		opt = DHCPOptRENEVALTIME()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.interval = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(interval):
		opt = DHCPOptRENEVALTIME()
		opt.interval = interval
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.interval.to_bytes(4, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= RENEVALTIME =\r\n'
		t += 'interval: %s\r\n' % str(self.interval)
		return t


class DHCPOptREBINDINGTIME():
	def __init__(self):
		self.code = 59
		self.len  = 4
		self.interval = None

	def from_buffer(buff):
		opt = DHCPOptREBINDINGTIME()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.interval = int.from_bytes(buff.read(4), byteorder = 'big', signed=False)
		return opt

	def construct(interval):
		opt = DHCPOptREBINDINGTIME()
		opt.interval = interval
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.interval.to_bytes(4, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '= REBINDINGTIME =\r\n'
		t += 'interval: %s\r\n' % str(self.interval)
		return t

class DHCPOptCLASSIDENTIFIER():
	def __init__(self):
		self.code = 60
		self.len  = None
		self.classid = None

	def from_buffer(buff):
		opt = DHCPOptCLASSIDENTIFIER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.classid = buff.read(opt.len).decode()
		return opt

	def construct(classid):
		opt = DHCPOptCLASSIDENTIFIER()
		opt.classid = classid
		opt.len = len(opt.classid.encode())
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.classid.encode()
		return t

	def __repr__(self):
		t  = '= CLASSIDENTIFIER =\r\n'
		t += 'classid: %s\r\n' % str(self.classid)
		return t

class DHCPOptCLIENTIDENTIFIER():
	def __init__(self):
		self.code = 61
		self.len  = None
		self.type = None
		self.clientid = None

	def from_buffer(buff):
		opt = DHCPOptCLIENTIDENTIFIER()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.type = DHCPHardwareType(int.from_bytes(buff.read(1), byteorder = 'big', signed=False))
		opt.clientid = buff.read(opt.len-1)
		return opt

	def construct(clienttype, clientid):
		opt = DHCPOptCLIENTIDENTIFIER()
		opt.clientid = clientid
		opt.len = len(opt.clientid)-1
		opt.type = clienttype
		return opt

	def to_bytes(self):
		t  = self.code.to_bytes(1, byteorder = 'big', signed = False)
		t += self.len.to_bytes(1, byteorder = 'big', signed = False)
		t += self.type.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.clientid
		return t

	def __repr__(self):
		t  = '= CLIENTIDENTIFIER =\r\n'
		t += 'clientid: %s\r\n' % str(self.clientid)
		return t

class DHCPOptXXX():
	def __init__(self):
		self.code = None
		self.len  = None
		self.data = None

	def from_buffer(buff):
		opt = DHCPOptXXX()
		opt.code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.len = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
		opt.data = buff.read(opt.len)
		return opt

	def __repr__(self):
		t  = '= XXX =\r\n'
		t += 'code: %s\r\n' % str(self.code)
		t += 'len: %s\r\n' % str(self.len)
		t += 'data: %s\r\n' % str(self.data.hex())
		return t

OPTCode2ClassName = {
	0  : DHCPOptPAD,
	1  : DHCPOptSUBNETMASK,
	2  : DHCPOptTIMEOFFSET,
	3  : DHCPOptROUTERS,
	4  : DHCPOptTIMESERVERS,
	5  : DHCPOptNAMESERVERS,
	6  : DHCPOptDNSSERVERS,
	7  : DHCPOptLOGSERVERS,
	8  : DHCPOptCOOKIESERVER,
	9  : DHCPOptLPRSERVERS,
	10 : DHCPOptIMPRESSSERVERS,
	11 : DHCPOptRESOURCELOCATIONS,
	12 : DHCPOptHOSTNAME,
	13 : DHCPOptBOOTFILESIZE,
	14 : DHCPOptMERITDUMPFILE,
	15 : DHCPOptDOMAINNAME,
	16 : DHCPOptSWAPSERVER,
	17 : DHCPOptROOTPATH,
	18 : DHCPOptEXTENSIONSPATH,
	19 : DHCPOptIPFORWARDING,
	20 : DHCPOptNONLOCALSRCROUTING,
	21 : DHCPOptPOLICYFILTER,
	22 : DHCPOptMAXIMUMDATAGRAMREASSEMBLY,
	23 : DHCPOptDEFAULTTTL,
	24 : DHCPOptPATHMTUAGINGTIMEOUT,
	25 : DHCPOptMTUPLATEUTABLE,
	26 : DHCPOptINTERFACEMTU,
	27 : DHCPOptALLSUBNETSARELOCAL,
	28 : DHCPOptBROADCASTADDRESS,
	29 : DHCPOptPERFORMMASKDISCOVERY,
	30 : DHCPOptMASKSUPPLIER,
	31 : DHCPOptPERFORMROUTERDISCOVERY,
	32 : DHCPOptROUTERSOLICITATIONADDRESS,
	33 : DHCPOptSTATICROUTES,
	34 : DHCPOptTRAILERENCAPSULATION,
	35 : DHCPOptARPCACHETIMEOUT,
	36 : DHCPOptETHERNETENCAPSULATION,
	37 : DHCPOptTCPDEFAULTTTL,
	38 : DHCPOptTCPKEEPALIVEINTERVAL,
	39 : DHCPOptTCPKEEPALIVEGARBAGE,
	40 : DHCPOptNISDOMAIN,
	41 : DHCPOptNIS,
	42 : DHCPOptNTP,
	43 : DHCPOptVENDORSPECIFIC,
	44 : DHCPOptNETBIOSOVERTCP,
	45 : DHCPOptNETBIOSOVERTCPDDS,
	46 : DHCPOptNETBIOSOVERTCPNODETYPE,
	47 : DHCPOptNETBIOSOVERTCPSCOPE,
	48 : DHCPOptXWINDOWFONTSERVER,
	49 : DHCPOptXWINDOWDISPLAYMANAGER,
	50 : DHCPOptREQUESTEDIPADDRESS,
	51 : DHCPOptIPADDRESSLEASETIME,
	52 : DHCPOptOPTIONOVERLOAD,
	53 : DHCPOptDHCPMESSAGETYPE,
	54 : DHCPOptSERVERIDENTIFIER,
	55 : DHCPOptPARAMETERREQUEST,
	56 : DHCPOptMESSAGE,
	57 : DHCPOptMAXIMUMDHCPMESSAGESIZE,
	58 : DHCPOptRENEVALTIME,
	59 : DHCPOptREBINDINGTIME,
	60 : DHCPOptCLASSIDENTIFIER,
	61 : DHCPOptCLIENTIDENTIFIER,
	255: DHCPOptEND
}

class DHCPOptionsParser():
	def __init__(self):
		pass

	def from_buffer(buff):
		options = []
		while True:
			pos = buff.tell()
			code = int.from_bytes(buff.read(1), byteorder = 'big', signed=False)
			buff.seek(pos, io.SEEK_SET)
			if code in OPTCode2ClassName:
				opt = OPTCode2ClassName[code].from_buffer(buff)
				options.append(opt)
				if opt.code == 255:
					break
			else:
				opt = DHCPOptXXX.from_buffer(buff)
				options.append(opt)

		return options
		
