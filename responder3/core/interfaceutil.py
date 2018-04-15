import platform
import ipaddress
import socket
from responder3.core.sockets import SocketConfig

"""
Linux implementation thankyous:
This code is based on the following implementation: https://gist.github.com/chadmiller/5157850#file-getnifs-py
In the original code it is mentioned that it's actually a modified version of: https://gist.github.com/provegard/1536682
Which was in fact based on the "getifaddrs.py" script from pydlnadms [http://code.google.com/p/pydlnadms/].

Windows implementations thankyous:
The windows version is based on the code from https://github.com/darkk 
https://github.com/darkk/tcp_shutter/blob/master/tcp_shutter.py

OSX (MAC) implementation thankyous:
Implementation was created for this project by EvilWan (https://github.com/evilwan)
"""


class NetworkInterfaces:
	def __init__(self):
		"""
		Provides a platform-independent way of enumerating all available interfaces and IP addresses on the host
		"""
		self.platform = platform.system()
		self.interfaces = {}
		self.name_ip_lookup = {}
		self.ip_name_lookup = {}
		self.iface_help = ''

		# enumerating interfaces
		self.enumerate_interfaces()
		# creating lookup tables, and help string to display on help menu
		self.generate_lookups_and_help()

	def enumerate_interfaces(self):
		"""
		Enumerates all interfaces on host
		:return: None
		"""
		if self.platform == 'Windows':
			self.interfaces = get_win_ifaddrs()

		elif self.platform == 'Linux':
			self.interfaces = get_linux_ifaddrs()

		elif self.platform == 'Darwin':
			self.interfaces = get_darwin_ifaddrs()

	def generate_lookups_and_help(self):
		"""
		Generates lookup dictionaries and a formatted string describing all interfaces and addresses
		:return: None
		"""
		self.iface_help += 'NAME\tIPv4\t\tIPv6\r\n'
		for iface in self.interfaces:
			addresses = [str(ip) for ip in self.interfaces[iface].addresses]
			self.iface_help += '\t'.join([iface, ','.join(addresses), '\r\n'])

			for ip in self.interfaces[iface].addresses:

				if (iface, ip.version) not in self.name_ip_lookup:
					self.name_ip_lookup[(iface, ip.version)] = []
				self.name_ip_lookup[(iface, ip.version)].append(ip)

				if ip in self.ip_name_lookup:
					print('Multiple interface found with the same IPv4 address! You will need to specify interface name in config')
				else:
					self.ip_name_lookup[ip] = iface

	def get_ifname(self, ip):
		"""
		Returns interface name belonging to the IP address provided in ip
		:param ip: IP address to search the interface for
		:type ip: ipaddress.IPv4Address or ipaddress.IPv6Address
		:return: str
		"""
		return self.ip_name_lookup.get(str(ip), None)

	def get_ip(self, ifname, ipversion = 4):
		"""
		Returns version 4 or 6 ip addresses for the interface specified by ifname.
		:param ifname: Name of the interface
		:type ifname: str
		:param ipversion: Specified ip address version to return
		:type ipversion: int
		:return: list
		"""
		return self.name_ip_lookup.get((ifname, ipversion), None)

	def get_socketconfig_from_ip(self, ip, port, protocol):
		"""
		Returns a SocketConfig object for the given ip, port, protocol
		:param ip: IP address belonging to an existing interface
		:param port: port numer
		:param protocol: protocol type
		:type protocol: socket.SOCK_STREAM or socket.SOCK_DGRAM
		:return: SocketConfig
		"""
		sc = SocketConfig()
		sc.bind_port = int(port)
		if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
			sc.bind_addr = ip
		else:
			sc.bind_addr = ipaddress.ip_address(ip)

		sc.bind_family = sc.bind_addr.version

		if isinstance(protocol, str):
			if protocol.lower() == 'tcp':
				sc.bind_protocol = socket.SOCK_STREAM
			elif protocol.lower() == 'udp':
				sc.bind_protocol = socket.SOCK_DGRAM
			else:
				raise Exception('Unknown protocol definition %s' % protocol)
		elif isinstance(protocol, int):
			sc.bind_protocol = protocol
		else:
			raise Exception('Unknown protocol definition %s' % protocol)

		sc.bind_iface = self.ip_name_lookup[sc.bind_addr]
		sc.bind_iface_idx = self.interfaces[sc.bind_iface].ifindex

		return sc

	def get_client_socketconfig(self, ifname, protocol, ipversion = None, reuse_address = False, reuse_port= False):
		if ifname not in self.interfaces:
			raise Exception('Could not find ifname %s!' % ifname)

		scl = []
		try:
			iv = []
			if ipversion is None:
				iv.append(4)
				iv.append(6)
			elif isinstance(ipversion, str):
				if int(ipversion) in [4,6]:
					iv.append(int(ipversion))
				else:
					raise Exception()

			elif isinstance(ipversion, int):
				if ipversion in [4,6]:
					iv.append(ipversion)
				else:
					raise Exception()

			elif isinstance(ipversion, list):
				iv = ipversion

		except Exception as e:
			raise Exception('Unknown IP version %s' % repr(ipversion))

		for version in iv:
			for lookup_ifname, ver in self.name_ip_lookup:
				if ifname != lookup_ifname:
					continue
				if ver != version:
					break
				for address in self.name_ip_lookup[(lookup_ifname, ver)]:
					sc = SocketConfig()
					sc.bind_port = 0
					sc.bind_addr = address
					sc.bind_family = sc.bind_addr.version

					if isinstance(protocol, str):
						if protocol.lower() == 'tcp':
							sc.bind_protocol = socket.SOCK_STREAM
						elif protocol.lower() == 'udp':
							sc.bind_protocol = socket.SOCK_DGRAM
						else:
							raise Exception('Unknown protocol definition %s' % protocol)
					elif isinstance(protocol, int):
						sc.bind_protocol = protocol
					else:
						raise Exception('Unknown protocol definition %s' % protocol)

					sc.bind_iface = ifname
					sc.bind_iface_idx = self.interfaces[sc.bind_iface].ifindex
					sc.is_server = False
					sc.reuse_address = reuse_address
					sc.reuse_port = reuse_port
					scl.append(sc)

		return scl


	def get_socketconfig(self, ifname, port, protocol, ipversion = None):
		"""
		Returns a list of socketconfig objects to create server.
		:param ifname: Interface name
		:type ifname: str
		:param port: Port number
		:type port: int
		:param protocol: Protocol type
		:type protocol: str or int or socket.SOCK_STREAM/socket.SOCK_DGRAM
		:param ipversion: IP address version
		:return: list of SocketConfig
		"""
		if ifname not in self.interfaces:
			raise Exception('Could not find ifname %s!' % ifname)

		scl = []
		try:
			iv = []
			if ipversion is None:
				iv.append(4)
				iv.append(6)
			elif isinstance(ipversion, str):
				if int(ipversion) in [4,6]:
					iv.append(int(ipversion))
				else:
					raise Exception()

			elif isinstance(ipversion, int):
				if ipversion in [4,6]:
					iv.append(ipversion)
				else:
					raise Exception()

			elif isinstance(ipversion, list):
				iv = ipversion

		except Exception as e:
			raise Exception('Unknown IP version %s' % repr(ipversion))

		for version in iv:
			for lookup_ifname, ver in self.name_ip_lookup:
				if ifname != lookup_ifname:
					continue
				if ver != version:
					break
				for address in self.name_ip_lookup[(lookup_ifname, ver)]:
					sc = SocketConfig()
					sc.bind_port = int(port)
					sc.bind_addr = address
					sc.bind_family = sc.bind_addr.version

					if isinstance(protocol, str):
						if protocol.lower() == 'tcp':
							sc.bind_protocol = socket.SOCK_STREAM
						elif protocol.lower() == 'udp':
							sc.bind_protocol = socket.SOCK_DGRAM
						else:
							raise Exception('Unknown protocol definition %s' % protocol)
					elif isinstance(protocol, int):
						sc.bind_protocol = protocol
					else:
						raise Exception('Unknown protocol definition %s' % protocol)

					sc.bind_iface = ifname
					sc.bind_iface_idx = self.interfaces[sc.bind_iface].ifindex
					sc.is_server = True
					scl.append(sc)

		return scl

	def __str__(self):
		return self.iface_help


class NetworkInterface:
	def __init__(self):
		"""
		Container object to describe a network interface
		"""
		self.ifname = None
		self.ifindex = None #zone_indices in windows
		self.addresses = []

	def __repr__(self):
		return str(self)
		
	def __str__(self):
		t  = '== INTERFACE ==\r\n'
		t += 'Name: %s\r\n' % self.ifname
		t += 'ifindex: %s\r\n' % self.ifindex
		for addr in self.addresses:
			t += 'Address: %s\r\n' % str(addr)
		
		return t

def get_linux_ifaddrs():
	"""
	Enumerates all network interfaces and all IP addresses assigned for each interfaces both IPv4 and IPv6 on Linux host
	:return: list of NetworkInterface
	"""
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
			if family in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
				interfacesd[ifname].addresses.append(ipaddress.ip_address(addr))
		return interfacesd
	finally:
		libc.freeifaddrs(ifap)

def get_win_ifaddrs():
	"""
	Enumerates all network interfaces and all IP addresses assigned for each interfaces both IPv4 and IPv6 on Windows host
	:return: list of NetworkInterface
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
		interface = NetworkInterface()
		interface.ifname  = i.description
		interface.ifindex = i.zone_indices #zone_indices in windows
		
		
		addresses = i.first_unicast_address
		
		while addresses:
			
			fu = addresses.contents
			
			ipversion = fu.address.address.v4.contents.family			
			if ipversion == AF_INET:
				ad = fu.address.address.v4.contents
				#print("\tfamily: {0}".format(ad.family))
				ip_int = struct.unpack('>2xI8x', ad.data)[0]
				interface.addresses.append(ipaddress.IPv4Address(ip_int))
			elif ipversion == AF_INET6:
				ad = fu.address.address.v6.contents
				ip_int = struct.unpack('!QQ', ad.addr.byte)[0]
				interface.addresses.append(ipaddress.IPv6Address(ip_int))
			
			addresses = addresses.contents.next
			
		interfaced[interface.ifname] = interface
	return interfaced
	

def get_darwin_ifaddrs():
	"""
	Enumerates all network interfaces and all IP addresses assigned for each interfaces both IPv4 and IPv6 on Macintosh host
	:return: list of NetworkInterface
	"""
	from socket import AF_INET, AF_INET6, inet_ntop
	from ctypes import (
		Structure, Union, POINTER,
		pointer, get_errno, cast,
		c_ushort, c_byte, c_uint8, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
	)
	import ctypes.util
	import ctypes

	class struct_sockaddr(Structure):
		_fields_ = [
			('sa_len', c_uint8),
			('sa_family', c_uint8),
			('sa_data', c_byte * 14),]

	class struct_sockaddr_in(Structure):
		_fields_ = [
			('sin_len', c_uint8),
			('sin_family', c_uint8),
			('sin_port', c_uint16),
			('sin_addr', c_uint8 * 4),
			('sin_zero', c_byte * 8),]

	class struct_sockaddr_in6(Structure):
		_fields_ = [
			('sin6_len', c_uint8),
			('sin6_family', c_ushort),
			('sin6_port', c_uint16),
			('sin6_flowinfo', c_uint32),
			('sin6_addr', c_byte * 16),
			('sin6_scope_id', c_uint32)]

	"""
	class union_ifa_ifu(Union):
			_fields_ = [
					('ifu_broadaddr', POINTER(struct_sockaddr)),
					('ifu_dstaddr', POINTER(struct_sockaddr)),]
	"""

	class struct_ifaddrs(Structure):
		pass
	struct_ifaddrs._fields_ = [
		('ifa_next', POINTER(struct_ifaddrs)),
		('ifa_name', c_char_p),
		('ifa_flags', c_uint),
		('ifa_addr', POINTER(struct_sockaddr)),
		('ifa_netmask', POINTER(struct_sockaddr)),
		('ifa_dstaddr', POINTER(struct_sockaddr)),
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
			interfacesd[ifname].addresses.append(ipaddress.ip_address(addr))
		return interfacesd
	finally:
		libc.freeifaddrs(ifap)


interfaces = NetworkInterfaces()
