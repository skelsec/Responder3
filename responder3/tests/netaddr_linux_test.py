#!/usr/bin/python

# Based on https://gist.github.com/provegard/1536682, which was
# Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
# Only tested on Linux!

from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import (
	Structure, Union, POINTER,
	pointer, get_errno, cast,
	c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes.util
import ctypes

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

"""
class NetworkInterface(object):
	def __init__(self, name):
		self.name = name
		self.index = libc.if_nametoindex(name)
		self.IPv4 = []
		self.IPv6 = []

	def __str__(self):
		return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
			self.name, self.index,
			self.addresses.get(AF_INET),
			self.addresses.get(AF_INET6))
"""

def get_network_interfaces():
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

if __name__ == '__main__':
	ifacesd = get_network_interfaces()
	for iface in ifacesd:
		print(ifacesd[iface])
