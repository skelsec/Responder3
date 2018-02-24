import platform

"""
Linux implementation thankyous:
This code is based on the following implementation: https://gist.github.com/chadmiller/5157850#file-getnifs-py
In the original code it is mentioned that it's actually a modified version of: https://gist.github.com/provegard/1536682
Which was in fact based on the "getifaddrs.py" script from pydlnadms [http://code.google.com/p/pydlnadms/].

Windows implementations thankyous:


https://github.com/darkk/tcp_shutter/blob/master/tcp_shutter.py
"""

class NetworkInterface():
	def __init__(self):
		self.ifname = None
		self.ifindex = None #zone_indices in windows
		self.IPv4 = []
		self.IPv6 = []

	def __repr__(self):
		return str(self)
		
	def __str__(self):
		t  = '== INTERFACE ==\r\n'
		t += 'Name: %s\r\n' % self.ifname
		t += 'ifindex: %s\r\n' % self.ifindex
		t += 'IPv4: %s\r\n' % self.IPv4
		t += 'IPv6: %s\r\n' % self.IPv6
		
		return t

def get_linux_ifaddrs():
	from socket import AF_INET, AF_INET6, inet_ntop
	from ctypes import (
		Structure, Union, POINTER,
		pointer, get_errno, cast,
		c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
	)
	import ctypes.util
	import ctypes

	class struct_sockaddr(Structure):
		_fields_ = [
			('sa_family', c_ushort),
			('sa_data', c_byte * 14),]

	class struct_sockaddr_in(Structure):
		_fields_ = [
			('sin_family', c_ushort),
			('sin_port', c_uint16),
			('sin_addr', c_byte * 4)]

	class struct_sockaddr_in6(Structure):
		_fields_ = [
			('sin6_family', c_ushort),
			('sin6_port', c_uint16),
			('sin6_flowinfo', c_uint32),
			('sin6_addr', c_byte * 16),
			('sin6_scope_id', c_uint32)]

	class union_ifa_ifu(Union):
		_fields_ = [
			('ifu_broadaddr', POINTER(struct_sockaddr)),
			('ifu_dstaddr', POINTER(struct_sockaddr)),]

	class struct_ifaddrs(Structure):
		pass
	struct_ifaddrs._fields_ = [
		('ifa_next', POINTER(struct_ifaddrs)),
		('ifa_name', c_char_p),
		('ifa_flags', c_uint),
		('ifa_addr', POINTER(struct_sockaddr)),
		('ifa_netmask', POINTER(struct_sockaddr)),
		('ifa_ifu', union_ifa_ifu),
		('ifa_data', c_void_p),]

	libc = ctypes.CDLL(ctypes.util.find_library('c'))

	def ifap_iter(ifap):
		ifa = ifap.contents
		while True:
			yield ifa
			if not ifa.ifa_next:
				break
			ifa = ifa.ifa_next.contents

	def getfamaddr(sa):
		family = sa.sa_family
		addr = None
		if family == AF_INET:
			sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
			addr = inet_ntop(family, sa.sin_addr)
		elif family == AF_INET6:
			sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
			addr = inet_ntop(family, sa.sin6_addr)
		return family, addr

	ifap = POINTER(struct_ifaddrs)()
	result = libc.getifaddrs(pointer(ifap))
	if result != 0:
		raise OSError(get_errno())
	del result
	try:
		interfacesd = {}
		for ifa in ifap_iter(ifap):
			ifname = ifa.ifa_name.decode("UTF-8")
			if ifname not in interfacesd:
				interfacesd[ifname] = NetworkInterface()
				interfacesd[ifname].ifname = ifname
				interfacesd[ifname].ifindex = libc.if_nametoindex(ifname)
			family, addr = getfamaddr(ifa.ifa_addr.contents)
			if family == AF_INET:
				interfacesd[ifname].IPv4.append(addr)
			elif family == AF_INET6:
				interfacesd[ifname].IPv6.append(addr)
		return interfacesd
	finally:
		libc.freeifaddrs(ifap)

def get_win_ifaddrs():
	"""
	A method for retrieving info of the network
	interfaces. Returns a nested dictionary of
	interfaces in Windows. Supports both IPv4 
	and IPv6 addresses
	"""
	import ctypes
	import struct
	import ipaddress
	import ctypes.wintypes
	from ctypes.wintypes import DWORD, WCHAR, BYTE, BOOL
	from socket import AF_INET, AF_UNSPEC, AF_INET6
	
	# from iptypes.h
	MAX_ADAPTER_ADDRESS_LENGTH = 8
	MAX_DHCPV6_DUID_LENGTH = 130

	GAA_FLAG_INCLUDE_PREFIX = ctypes.c_ulong(0x0010)
	
	class SOCKADDR(ctypes.Structure):
		_fields_ = [
			('family', ctypes.c_ushort),
			('data', ctypes.c_byte*14),
			]
	LPSOCKADDR = ctypes.POINTER(SOCKADDR)
	
	class IN6_ADDR(ctypes.Structure):
		_fields_ = [
			('byte', ctypes.c_byte*16),
			('word', ctypes.c_byte*16), #this should be changed
			]
	
	class SOCKADDR_IN6(ctypes.Structure):
		_fields_ = [
			('family', ctypes.c_short),
			('port', ctypes.c_ushort),
			('flowinfo', ctypes.c_ulong),
			('addr', IN6_ADDR),
			('scope_id', ctypes.c_ulong),
			]
	LPSOCKADDR_IN6 = ctypes.POINTER(SOCKADDR_IN6)
	

	# NB: It's not true mapping of `sockaddr_storage` structure!
	class SOCKADDR_STORAGE(ctypes.Union):
		_fields_ = (('v4', LPSOCKADDR), ('v6', LPSOCKADDR_IN6))

	class SOCKET_ADDRESS(ctypes.Structure):
		_fields_ = [
			#('address', LPSOCKADDR),
			('address', SOCKADDR_STORAGE),
			('length', ctypes.c_int),
			]

	class _IP_ADAPTER_ADDRESSES_METRIC(ctypes.Structure):
		_fields_ = [
			('length', ctypes.c_ulong),
			('interface_index', DWORD),
			]

	class _IP_ADAPTER_ADDRESSES_U1(ctypes.Union):
		_fields_ = [
			('alignment', ctypes.c_ulonglong),
			('metric', _IP_ADAPTER_ADDRESSES_METRIC),
			]

	class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
		pass
	PIP_ADAPTER_UNICAST_ADDRESS = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)
	IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
			("length", ctypes.c_ulong),
			("flags", ctypes.wintypes.DWORD),
			("next", PIP_ADAPTER_UNICAST_ADDRESS),
			("address", SOCKET_ADDRESS),
			("prefix_origin", ctypes.c_int),
			("suffix_origin", ctypes.c_int),
			("dad_state", ctypes.c_int),
			("valid_lifetime", ctypes.c_ulong),
			("preferred_lifetime", ctypes.c_ulong),
			("lease_lifetime", ctypes.c_ulong),
			("on_link_prefix_length", ctypes.c_ubyte)
			]

	# it crashes when retrieving prefix data :(
	class IP_ADAPTER_PREFIX(ctypes.Structure):
		pass
	PIP_ADAPTER_PREFIX = ctypes.POINTER(IP_ADAPTER_PREFIX)
	IP_ADAPTER_PREFIX._fields_ = [
		("alignment", ctypes.c_ulonglong),
		("next", PIP_ADAPTER_PREFIX),
		("address", SOCKET_ADDRESS),
		("prefix_length", ctypes.c_ulong)
		]

	class IP_ADAPTER_ADDRESSES(ctypes.Structure):
		pass
	LP_IP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
	
	# for now, just use void * for pointers to unused structures
	PIP_ADAPTER_ANYCAST_ADDRESS = ctypes.c_void_p
	PIP_ADAPTER_MULTICAST_ADDRESS = ctypes.c_void_p
	PIP_ADAPTER_DNS_SERVER_ADDRESS = ctypes.c_void_p
	#PIP_ADAPTER_PREFIX = ctypes.c_void_p
	PIP_ADAPTER_WINS_SERVER_ADDRESS_LH = ctypes.c_void_p
	PIP_ADAPTER_GATEWAY_ADDRESS_LH = ctypes.c_void_p
	PIP_ADAPTER_DNS_SUFFIX = ctypes.c_void_p

	IF_OPER_STATUS = ctypes.c_uint # this is an enum, consider http://code.activestate.com/recipes/576415/
	IF_LUID = ctypes.c_uint64

	NET_IF_COMPARTMENT_ID = ctypes.c_uint32
	GUID = ctypes.c_byte*16
	NET_IF_NETWORK_GUID = GUID
	NET_IF_CONNECTION_TYPE = ctypes.c_uint # enum
	TUNNEL_TYPE = ctypes.c_uint # enum

	IP_ADAPTER_ADDRESSES._fields_ = [
		#('u', _IP_ADAPTER_ADDRESSES_U1),
			('length', ctypes.c_ulong),
			('interface_index', DWORD),
		('next', LP_IP_ADAPTER_ADDRESSES),
		('adapter_name', ctypes.c_char_p),
		('first_unicast_address', PIP_ADAPTER_UNICAST_ADDRESS),
		('first_anycast_address', PIP_ADAPTER_ANYCAST_ADDRESS),
		('first_multicast_address', PIP_ADAPTER_MULTICAST_ADDRESS),
		('first_dns_server_address', PIP_ADAPTER_DNS_SERVER_ADDRESS),
		('dns_suffix', ctypes.c_wchar_p),
		('description', ctypes.c_wchar_p),
		('friendly_name', ctypes.c_wchar_p),
		('byte', BYTE*MAX_ADAPTER_ADDRESS_LENGTH),
		('physical_address_length', DWORD),
		('flags', DWORD),
		('mtu', DWORD),
		('interface_type', DWORD),
		('oper_status', IF_OPER_STATUS),
		('ipv6_interface_index', DWORD),
		('zone_indices', DWORD),
		('first_prefix', PIP_ADAPTER_PREFIX),
		('transmit_link_speed', ctypes.c_uint64),
		('receive_link_speed', ctypes.c_uint64),
		('first_wins_server_address', PIP_ADAPTER_WINS_SERVER_ADDRESS_LH),
		('first_gateway_address', PIP_ADAPTER_GATEWAY_ADDRESS_LH),
		('ipv4_metric', ctypes.c_ulong),
		('ipv6_metric', ctypes.c_ulong),
		('luid', IF_LUID),
		('dhcpv4_server', SOCKET_ADDRESS),
		('compartment_id', NET_IF_COMPARTMENT_ID),
		('network_guid', NET_IF_NETWORK_GUID),
		('connection_type', NET_IF_CONNECTION_TYPE),
		('tunnel_type', TUNNEL_TYPE),
		('dhcpv6_server', SOCKET_ADDRESS),
		('dhcpv6_client_duid', ctypes.c_byte*MAX_DHCPV6_DUID_LENGTH),
		('dhcpv6_client_duid_length', ctypes.c_ulong),
		('dhcpv6_iaid', ctypes.c_ulong),
		('first_dns_suffix', PIP_ADAPTER_DNS_SUFFIX),
		]

	def GetAdaptersAddresses():
		"""
		Returns an iteratable list of adapters
		""" 
		size = ctypes.c_ulong()
		GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
		GetAdaptersAddresses.argtypes = [
			ctypes.c_ulong,
			ctypes.c_ulong,
			ctypes.c_void_p,
			ctypes.POINTER(IP_ADAPTER_ADDRESSES),
			ctypes.POINTER(ctypes.c_ulong),
		]
		GetAdaptersAddresses.restype = ctypes.c_ulong
		#res = GetAdaptersAddresses(AF_INET,0,None, None,size)
		res = GetAdaptersAddresses(AF_UNSPEC,0,None, None,size)
		if res != 0x6f: # BUFFER OVERFLOW
			raise RuntimeError("Error getting structure length (%d)" % res)
		pointer_type = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
		size.value = 15000
		buffer = ctypes.create_string_buffer(size.value)
		struct_p = ctypes.cast(buffer, pointer_type)
		#res = GetAdaptersAddresses(AF_INET,0,None, struct_p, size)
		res = GetAdaptersAddresses(AF_UNSPEC,0,None, struct_p, size)
		if res != 0x0: # NO_ERROR:
			raise RuntimeError("Error retrieving table (%d)" % res)
		while struct_p:
			yield struct_p.contents
			struct_p = struct_p.contents.next

	interfaced = {}
	for i in GetAdaptersAddresses():
		result = NetworkInterface()
		result.ifname  = i.description
		result.ifindex = i.zone_indices #zone_indices in windows
		
		
		addresses = i.first_unicast_address
		result.IPv4 = []
		result.IPv6 = []
		
		while addresses:
			
			fu = addresses.contents
			
			ipversion = fu.address.address.v4.contents.family			
			if ipversion == AF_INET:
				ad = fu.address.address.v4.contents
				#print("\tfamily: {0}".format(ad.family))
				ip_int = struct.unpack('>2xI8x', ad.data)[0]
				ip = ipaddress.IPv4Address(ip_int)
				#print(ip)
				result.IPv4.append(ip)
			elif ipversion == AF_INET6:
				ad = fu.address.address.v6.contents
				ip_int = struct.unpack('!QQ', ad.addr.byte)[0]
				ip = ipaddress.IPv6Address(ip_int)
				result.IPv6.append(ip)
			
			addresses = addresses.contents.next
			
		interfaced[result.ifname] = result
	return interfaced
	

interfaced = None
os_name = platform.system()
if os_name == 'Windows':
	interfaced = get_win_ifaddrs()

elif os_name == 'Linux':
	interfaced = get_linux_ifaddrs()

elif os_name == 'Darwin':
	raise Exception('Get interface list on MAC OS not implemented!')
