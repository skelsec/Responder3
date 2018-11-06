import ipaddress
from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import (
    Structure, POINTER,
    pointer, cast,
    c_ushort, c_byte, c_uint8, c_void_p, c_char_p, c_uint, c_uint16, c_uint32
)
import ctypes.util
import ctypes

from responder3.core.interfaces.NetworkInterface import NetworkInterface

def get_darwin_ifaddrs():
    """
    Enumerates all network interfaces and all IP addresses assigned for each interfaces both IPv4 and IPv6 on Macintosh host
    :return: list of NetworkInterface
    """

    class struct_sockaddr(Structure):
        _fields_ = [
            ('sa_len', c_uint8),
            ('sa_family', c_uint8),
            ('sa_data', c_byte * 14),]

    class struct_sockaddr_in4(Structure):
        _fields_ = [
            ('sin_len', c_uint8),
            ('sin_family', c_uint8),
            ('sin_port', c_uint16),
            ('sin_addr', c_uint8 * 4),
            ('sin_zero', c_byte * 8),]

    class struct_sockaddr_in6(Structure):
        _fields_ = [
            ('sin_len', c_uint8),
            ('sin_family', c_ushort),
            ('sin_port', c_uint16),
            ('sin_flowinfo', c_uint32),
            ('sin_addr', c_byte * 16),
            ('sin_scope_id', c_uint32)]

    struct_sockaddr_in = {}
    struct_sockaddr_in[AF_INET] = struct_sockaddr_in4
    struct_sockaddr_in[AF_INET6] = struct_sockaddr_in6

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
        while ifa:
            yield ifa
            if not ifa.ifa_next:
                break
            ifa = ifa.ifa_next.contents

    def get_family_and_address(sa):
        family = sa.sa_family
        addr = None
        if family not in [AF_INET, AF_INET6]:
            return family, None
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in[family])).contents
        addr = inet_ntop(family, sa.sin_addr)
        return family, addr

    ifap = POINTER(struct_ifaddrs)()
    libc.getifaddrs(pointer(ifap))
    interfacesd = {}
    try:
        for ifa in ifap_iter(ifap):
            ifname = ifa.ifa_name.decode("UTF-8")
            if ifname not in interfacesd:
                interfacesd[ifname] = NetworkInterface()
                interfacesd[ifname].ifname = ifname
                interfacesd[ifname].ifindex = libc.if_nametoindex(ifname)
            family, addr = get_family_and_address(ifa.ifa_addr.contents)
            if (addr is None):
                del interfacesd[ifname]
                continue
            interfacesd[ifname].addresses.append(ipaddress.ip_address(addr))
        return interfacesd
    finally:
        libc.freeifaddrs(ifap)
