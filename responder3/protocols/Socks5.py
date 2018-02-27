#https://www.ietf.org/rfc/rfc1928.txt
#https://tools.ietf.org/html/rfc1929
#https://tools.ietf.org/html/rfc1961

import io
import enum
import ipaddress

from responder3.utils import ServerProtocol

class SOCKS5ServerMode(enum.Enum):
        OFF    = enum.auto()
        NORMAL = enum.auto()
        EVIL   = enum.auto()

class SOCKS5ServerState(enum.Enum):
        NEGOTIATION = 0
        NOT_AUTHENTICATED = 1
        REQUEST = 3 
        RELAYING = 4

class SOCKS5Method(enum.Enum):
        NOAUTH = 0x00
        GSSAPI = 0x01
        PLAIN  = 0x02
        ##IANA ASSIGNED X'03' to X'7F' 
        ##RESERVED FOR PRIVATE METHODS X'80' to X'FE' 

        NOTACCEPTABLE = 0xFF

class SOCKS5Command(enum.Enum):
        CONNECT = 0x01
        BIND = 0x02
        UDP_ASSOCIATE = 0x03

class SOCKS5AddressType(enum.Enum):
        IP_V4 = 0x01
        DOMAINNAME = 0x03
        IP_V6 = 0x04

class SOCKS5ReplyType(enum.Enum):
        SUCCEEDED = 0X00 #o  X'00' succeeded
        FAILURE = 0x01 #o  X'01' general SOCKS server failure
        CONN_NOT_ALLOWED = 0x02#         o  X'02' connection not allowed by ruleset
        NETWORK_UNREACHABLE = 0x03 #o  X'03' Network unreachable
        HOST_UNREACHABLE = 0x04#o  X'04' Host unreachable
        CONN_REFUSED = 0x05 #o  X'05' Connection refused
        TTL_EXPIRED = 0x06 #o  X'06' TTL expired
        COMMAND_NOT_SUPPORTED = 0x07 #o  X'07' Command not supported
        ADDRESS_TYPE_NOT_SUPPORTED = 0x08 #o  X'08' Address type not supported
        #o  X'09' to X'FF' unassigned


class SOCKS5SocketParser():
        def __init__(self, protocol = ServerProtocol.TCP):
                self.protocol = protocol

        def parse(self, soc, packet_type):
                return packet_type.from_bytes(self.read_soc(soc, packet_type.size))

        def read_soc(self, soc, size):
                data = b''
                while True:
                        temp = soc.recv(4096)
                        if temp == '':
                                break
                        data += temp
                        if len(data) == size:
                                break
                return data

class SOCKS5CommandParser():
        def __init__(self, protocol = ServerProtocol.TCP):
                self.protocol = protocol

        def parse(self, buff, session):
                if session.currentState == SOCKS5ServerState.NEGOTIATION:
                        return SOCKS5Nego.from_buffer(buff)
                
                if session.currentState == SOCKS5ServerState.NOT_AUTHENTICATED:
                        if session.mutualAuthType == SOCKS5Method.PLAIN:
                                return SOCKS5PlainAuth.from_buffer(buff)
                        else:
                                raise Exception('Not implemented!')

                if session.currentState == SOCKS5ServerState.REQUEST:
                        return SOCKS5Request.from_buffer(buff)

class SOCKS5AuthHandler():
        def __init__(self, authType, creds = None):
                self.authType  = authType
                self.creds = creds

        def do_AUTH(self, msg):
                if self.authType == SOCKS5Method.PLAIN:
                        if not isinstance(msg, SOCKS5PlainAuth):
                                raise Exception('Wrong message/auth type!')

                        if self.creds is None:
                                return True, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)
                        else:
                                if msg.UNAME in self.creds:
                                        if msg.PASSWD == self.creds[msg.UNAME]:
                                                return True, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)

                                return False, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)

                elif self.authType == SOCKS5Method.GSSAPI:
                        raise Exception('Not implemented! yet')
                
                else:
                        raise Exception('Not implemented!')

class SOCKS5PlainCredentials():
        def __init__(self, username, password):
                self.username = username
                self.password = password

        def toResult(self):
                res = {
                        'type'     : 'PLAIN', 
                        'user'     : self.username,
                        'cleartext': self.password,
                        'fullhash' : '%s:%s' % (self.username, self.password)
                }
                return res


class SOCKS5PlainAuth():
        def __init__(self):
                self.VER = None
                self.ULEN = None
                self.UNAME = None
                self.PLEN = None
                self.PASSWD = None

        def from_bytes(bbuff):
                return SOCKS5PlainAuth.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                auth = SOCKS5PlainAuth()
                auth.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                auth.ULEN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
                auth.UNAME = buff.read(auth.ULEN).decode()
                auth.PLEN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
                auth.PASSWD = buff.read(auth.PLEN).decode()

                return auth

        def constrcut(username, password):
                auth = SOCKS5PlainAuth()
                auth.VER    = 5
                auth.ULEN   = len(username)
                auth.UNAME  = username
                auth.PLEN   = len(password)
                auth.PASSWD = password

                return auth

        def toBytes(self):
                t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
                t += self.ULEN.to_bytes(1, byteorder = 'big', signed = False)
                t += self.UNAME.encode()
                t += self.PLEN.to_bytes(1, byteorder = 'big', signed = False)
                t += self.PASSWD.encode()
                return t


class SOCKS5Nego():
        def __init__(self):
                self.VER = None
                self.NMETHODS = None
                self.METHODS = None

        def from_bytes(bbuff):
                return SOCKS5Nego.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                nego = SOCKS5Nego()
                nego.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                nego.NMETHODS = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                nego.METHODS = []
                for i in range(nego.NMETHODS):
                        nego.METHODS.append(SOCKS5Method(int.from_bytes(buff.read(1), byteorder = 'big', signed = False)))
                return nego

        def construct(methods):
                if not isinstance(methods, list):
                        methods = [methods]
                nego = SOCKS5Nego()
                nego.VER = 5
                nego.NMETHODS = len(methods)
                nego.METHODS = methods
                return nego

        def toBytes(self):
                t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
                t += self.NMETHODS.to_bytes(1, byteorder = 'big', signed = False)
                for method in self.METHODS:
                        t += method.value.to_bytes(1, byteorder = 'big', signed = False)
                return t

class SOCKS5NegoReply():
        def __init__(self):
                self.VER = None
                self.METHOD = None

        def from_socket(soc):
                data = b''
                total_size = 2
                while True:
                        temp = soc.recv(1024)
                        if temp == b'':
                                break
                        data += temp
                        if len(data) >= total_size:
                                break
                print(data)
                return SOCKS5NegoReply.from_bytes(data)
        
        def from_bytes(bbuff):
                return SOCKS5NegoReply.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                rep = SOCKS5NegoReply()
                rep.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
                rep.METHOD = SOCKS5Method(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
                return rep

        def construct(method):
                rep = SOCKS5NegoReply()
                rep.VER = 5
                rep.METHOD = method
                return rep

        def construct_auth(method, ver = 1):
                rep = SOCKS5NegoReply()
                rep.VER = ver
                rep.METHOD = method
                return rep


        def toBytes(self):
                t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
                t += self.METHOD.value.to_bytes(1, byteorder = 'big', signed = False)
                return t



class SOCKS5Request():
        def __init__(self):
                self.VER = None
                self.CMD = None
                self.RSV = None
                self.ATYP = None
                self.DST_ADDR = None
                self.DST_PORT = None

        def from_bytes(bbuff):
                return SOCKS5Request.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                req = SOCKS5Request()
                req.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                req.CMD = SOCKS5Command(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
                req.RSV = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                req.ATYP = SOCKS5AddressType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False)) 
                if req.ATYP == SOCKS5AddressType.IP_V4:
                        req.DST_ADDR = ipaddress.IPv4Address(buff.read(4))
                elif req.ATYP == SOCKS5AddressType.IP_V6:
                        req.DST_ADDR = ipaddress.IPv6Address(buff.read(16))
                elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
                        length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                        req.DST_ADDR = buff.read(length).decode()

                req.DST_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
                return req

        def construct(cmd, address, port):
                req = SOCKS5Request()
                req.VER = 5
                req.CMD = cmd
                req.RSV = 0
                if isinstance(address, ipaddress.IPv4Address):
                        req.ATYP = SOCKS5AddressType.IP_V4
                        req.DST_ADDR = address
                elif isinstance(address, ipaddress.IPv6Address):
                        req.ATYP = SOCKS5AddressType.IP_V6
                        req.DST_ADDR = address
                elif isinstance(address, str):
                        req.ATYP = SOCKS5AddressType.DOMAINNAME
                        req.DST_ADDR = address

                req.DST_PORT = port
                return req

        def toBytes(self):
                t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
                t += self.CMD.value.to_bytes(1, byteorder = 'big', signed = False)
                t += self.RSV.to_bytes(1, byteorder = 'big', signed = False)
                t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
                if self.ATYP == SOCKS5AddressType.DOMAINNAME:
                        t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
                        t += self.DST_ADDR.encode()
                else:        
                        t += self.DST_ADDR.packed
                t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
                return t

class SOCKS5Reply():
        def __init__(self):
                self.VER = None
                self.REP = None
                self.RSV = None
                self.ATYP = None
                self.BIND_ADDR= None
                self.BIND_PORT= None

        def from_socket(soc):
                data = b''
                total_size = 1024
                while True:
                        temp = soc.recv(1024)
                        if temp == b'':
                                break
                        data += temp
                        

                        if len(data) > 4:
                                rt = SOCKS5AddressType(data[3])
                                print(rt)
                                if rt == SOCKS5AddressType.IP_V4:
                                        total_size = 4 + 2 + 4
                                if rt == SOCKS5AddressType.IP_V6:
                                        total_size = 4 + 2 + 16
                                if rt == SOCKS5AddressType.DOMAINNAME:
                                        total_size = 4 + 2 + data[4]
                                print(total_size)
                        if len(data) >= total_size:
                                break

                return SOCKS5Reply.from_bytes(data)



        def from_bytes(bbuff):
                return SOCKS5Reply.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                rep = SOCKS5Reply()
                rep.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                rep.REP = SOCKS5ReplyType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
                rep.RSV = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
                rep.ATYP = SOCKS5AddressType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))

                if rep.ATYP == SOCKS5AddressType.IP_V4:
                        rep.BIND_ADDR = ipaddress.IPv4Address(buff.read(4))
                elif req.ATYP == SOCKS5AddressType.IP_V6:
                        rep.BIND_ADDR = ipaddress.IPv6Address(buff.read(16))
                elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
                        length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                        rep.BIND_ADDR = buff.read(length).decode()

                rep.BIND_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)

                return rep

        def construct(reply, address, port): 
                rep = SOCKS5Reply()
                rep.VER = 5
                rep.REP = reply
                rep.RSV = 0
                if isinstance(address, ipaddress.IPv4Address):
                        rep.ATYP = SOCKS5AddressType.IP_V4
                        rep.DST_ADDR = address
                elif isinstance(address, ipaddress.IPv6Address):
                        rep.ATYP = SOCKS5AddressType.IP_V6
                        rep.DST_ADDR = address
                elif isinstance(address, str):
                        rep.ATYP = SOCKS5AddressType.DOMAINNAME
                        rep.DST_ADDR = address

                rep.DST_PORT = port
                return rep

        def toBytes(self):
                t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
                t += self.REP.value.to_bytes(1, byteorder = 'big', signed = False)
                t += self.RSV.to_bytes(1, byteorder = 'big', signed = False)
                t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
                if self.ATYP == SOCKS5AddressType.DOMAINNAME:
                        t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
                        t += self.DST_ADDR.encode()
                else:        
                        t += self.DST_ADDR.packed
                t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
                return t

        def __repr__(self):
                t  = '== SOCKS5Reply ==\r\n'
                t += 'REP: %s\r\n' % repr(self.REP)
                t += 'ATYP: %s\r\n' % repr(self.ATYP)
                t += 'BIND_ADDR: %s\r\n' % repr(self.BIND_ADDR)
                t += 'BIND_PORT: %s\r\n' % repr(self.BIND_PORT)

                return t


class SOCKS5UDP():
        def __init__(self):
                self.RSV = None
                self.FRAG = None
                self.ATYP = None
                self.DST_ADDR = None
                self.DST_PORT = None
                self.DATA = None

        def from_bytes(bbuff):
                return SOCKS5UDP.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                rep = SOCKS5UDP()
                rep.RSV = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
                rep.FRAG = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
                rep.ATYP = int.SOCKS5AddressType(buff.read(1), byteorder = 'big', signed = False)
                if rep.ATYP == SOCKS5AddressType.IP_V4:
                        rep.BIND_ADDR = ipaddress.IPv4Address(buff.read(4))
                elif req.ATYP == SOCKS5AddressType.IP_V6:
                        rep.BIND_ADDR = ipaddress.IPv6Address(buff.read(16))
                elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
                        length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
                        rep.BIND_ADDR = buff.read(length).decode()

                rep.BIND_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
                #be careful, not data length is defined in the RFC!!
                rep.DATA = buff.read()


        def construct(address, port, data, frag = 0):
                req = SOCKS5Request()
                req.RSV = 0
                req.FRAG = frag
                if isinstance(address, ipaddress.IPv4Address):
                        req.ATYP = SOCKS5AddressType.IP_V4
                        req.DST_ADDR = address
                elif isinstance(address, ipaddress.IPv6Address):
                        req.ATYP = SOCKS5AddressType.IP_V6
                        req.DST_ADDR = address
                elif isinstance(address, str):
                        req.ATYP = SOCKS5AddressType.DOMAINNAME
                        req.DST_ADDR = address

                req.DST_PORT = port
                req.DATA = data
                return req

        def toBytes(self):
                t  = self.RSV.to_bytes(2, byteorder = 'big', signed = False)
                t += self.FRAG.value.to_bytes(1, byteorder = 'big', signed = False)
                t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
                if self.ATYP == SOCKS5AddressType.DOMAINNAME:
                        t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
                        t += self.DST_ADDR.encode()
                else:        
                        t += self.DST_ADDR.packed
                t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
                t += self.DATA
                return t