import ipaddress
import socket

from responder3.core.interfaces.NetworkInterface import NetworkInterface

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
			if ifa.ifa_addr:
				family, addr = getfamaddr(ifa.ifa_addr.contents)
			if family in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
				interfacesd[ifname].addresses.append(ipaddress.ip_address(addr))
		return interfacesd
	finally:
		libc.freeifaddrs(ifap)

