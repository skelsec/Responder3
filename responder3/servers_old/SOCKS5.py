import traceback
import logging
import io
import os
import re
import copy
import time
import asyncio
import socket
import threading
import collections
from ipaddress import IPv4Address, IPv6Address
from responder3.core.common import *
from responder3.utils import ServerFunctionality
from responder3.core.servertemplate import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.protocols.Socks5 import *

"""
TODO: fix the settings parsing!
re-test everything
"""

class SOCKS5Session(ProtocolSession):
        def __init__(self):
                ProtocolSession.__init__(self)
                self.cmdParser      = SOCKS5CommandParser()
                self.currentState   = SOCKS5ServerState.NEGOTIATION
                self.mutualAuthType = None
                self.authHandler    = None
                self.clientTransport= None

"""
proxyTable = [
        {
                re.compile('alma.com'): [
                        {
                                range(1,500) : '127.0.0.1'
                        }
                ]
        },
]
"""

class TCPProxyClientProtocol(asyncio.Protocol):
        def __init__(self, serverTransport, rdns, logQ):
                asyncio.Protocol.__init__(self)#serverTransport, rdns, logQ
                self.logQ = logQ
                self.serverTransport = serverTransport
                self.transport = None
                self.connection = Connection(rdns)
        
        def modulename(self):
                return 'TCPProxyClient'

        def log(self, level, message):
                self.logQ.put(LogEntry(level, self.modulename(), '[%s:%d] %s' % (self.connection.remote_ip, self.connection.remote_port, message)))

        def logConnection(self):
                if self.connection.status == ConnectionStatus.OPENED:
                        self.log(logging.INFO, 'New connection opened')

                elif self.connection.status == ConnectionStatus.CLOSED:
                        self.log(logging.INFO, 'Connection closed')
                self.logQ.put(self.connection)

        def data_received(self, raw_data):
                self.serverTransport.write(raw_data)

        def connection_made(self, transport):
                self.connection.setupTCP(transport.get_extra_info('socket'), ConnectionStatus.OPENED)
                self.logConnection()
                self.transport = transport

        def connection_lost(self, exc):
                self.connection.status = ConnectionStatus.CLOSED
                self.logConnection()


@asyncio.coroutine
def create_clinet_connection(dest_addr, dest_port, transport, session, server):
        clientTransport, clientProtocol = yield from server.loop.create_connection(
                                                                                                                        lambda: TCPProxyClientProtocol(transport, session.connection.rdnsd, server.logQ), 
                                                                                                                        host = dest_addr, 
                                                                                                                        port = dest_port)
        return clientTransport

class SOCKS5Protocol(ResponderProtocolTCP):
        def __init__(self, server):
                ResponderProtocolTCP.__init__(self, server)
                self._buffer_maxsize = 1024*1024
                self._session = copy.deepcopy(server.protocolSession)

        def _parsebuff(self):
                if self._session.currentState != SOCKS5ServerState.RELAYING:
                        buff = io.BytesIO(self._buffer)
                        cmd = self._session.cmdParser.parse(buff, self._session)
                        #after parsing it we send it for processing to the handle
                        self._server.handle(cmd, self._transport, self._session)

                        self._buffer = buff.read()
                        
                        if self._buffer != b'':
                                self._parsebuff()

                else:
                        #self._session.remote_writer.write(self._buffer)
                        #self._session.proxy_soc.sendall(self._buffer)
                        self._session.clientTransport.write(self._buffer)
                        
                        self._buffer = b''

class SOCKS5(ResponderServer):
        def __init__(self):
                ResponderServer.__init__(self)
                ### BE CAREFUL, THE proxyTable IS NOT PART OF THE SESSION OBJECT!
                self.proxyTable = collections.OrderedDict()
                self.supportedAuthTypes = [SOCKS5Method.PLAIN]
                self.creds = {'admin':'admin'}
                self.proxyMode = SOCKS5ServerMode.NORMAL
                self.allinterface   = IPv4Address('0.0.0.0') #TODO: change this tp '::'if IPv6 is used


        def setup(self):
                self.protocol = SOCKS5Protocol
                self.protocolSession = SOCKS5Session()

                self.creds = None
                if 'creds' in self.settings:
                        self.creds = self.settings['creds']

                self.supportedAuthTypes = [SOCKS5Method.PLAIN]
                if 'authType' in self.settings:
                        self.supportedAuthTypes = []
                        at = self.settings['authType']
                        if not isinstance(self.settings['authType'], list):
                                at = [self.settings['authType']]
                        for textAuthType in at:
                                self.supportedAuthTypes.append(SOCKS5Method[textAuthType.upper()])


                self.proxyMode = SOCKS5ServerMode.OFF
                if 'proxyMode' in self.settings:
                        self.proxyMode = SOCKS5ServerMode[self.settings['proxyMode'].upper()]
                
                if self.proxyMode == SOCKS5ServerMode.EVIL:
                        if 'proxyTable' not in self.settings:
                                raise Exception('EVIL mode requires proxyTable to be specified!')

                        #ughh...
                        for entry in self.settings['proxyTable']:
                                for ip in entry:
                                        iprex = re.compile(ip)
                                        self.proxyTable[iprex] = []
                                        for portranged in entry[ip]:
                                                for portrange in portranged:
                                                        if portrange.find('-') != -1:
                                                                start, stop = portrange.split('-')
                                                                prange = range(int(start.strip()),int(stop.strip())+1)
                                                
                                                        else:
                                                                prange = range(int(portrange),int(portrange)+1)
                                                        
                                                        if portranged[portrange].find(':') != -1:
                                                                #additional parsing to enable IPv6 addresses...
                                                                marker = portranged[portrange].rfind(':')
                                                                self.proxyTable[iprex].append({prange : (portranged[portrange][:marker], int(portranged[portrange][marker+1:]))})
                                                        else:
                                                                raise Exception('The target address MUST be supplied in IP:PORT format! Problem: %s' % portranged[portrange])

        def modulename(self):
                return 'SOCKS5'

        def fake_dest_lookup(self, dest_ip, dest_port):
                for ipregx in self.proxyTable:
                        if ipregx.match(dest_ip):
                                for portranged in self.proxyTable[ipregx]:
                                        for portrange in portranged:
                                                if dest_port in portrange:
                                                        return portranged[portrange]

                return None, None

        def start_proxy(self, dest_ip, dest_port, transport, session):
                
                #asyncio.Task(self.proxy_open_connection(str(packet.DST_ADDR), packet.DST_PORT, transport, session))
                #asyncio.Task(self.proxy_reader(transport, session))
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                        s.connect((dest_ip, dest_port))
                except ConnectionRefusedError:
                        transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.CONN_REFUSED, self.allinterface, 0).toBytes())
                        transport.close((dest_ip, dest_port))
                        return
                except Exception as e:
                        print(str(e))
                        transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.FAILURE, self.allinterface, 0).toBytes())
                        transport.close()
                        return

                try:
                        session.proxy_soc = s

                        session.currentState = SOCKS5ServerState.RELAYING
                        transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.allinterface, 0).toBytes())

                        session.proxy_control = threading.Event()
                        session.proxy_thread = threading.Thread(target=proxy, args=(s,transport, session.proxy_control))
                        session.proxy_thread.start()
                        self.log(logging.INFO,'Started proxying to %s:%d' % (dest_ip, dest_port), session)
                
                except Exception as e:
                        print(str(e))
                        

                return

        def handle(self, packet, transport, session):
                try:
                        if 'R3DEEPDEBUG' in os.environ:
                                self.log(logging.INFO,'Session state: %s Command: %s' % (session.currentState.name, type(packet) if packet is not None else 'NONE'), session)
                        #should be checking which commands are allowed in this state...
                        if session.currentState == SOCKS5ServerState.NEGOTIATION:
                                mutual = list(set(self.supportedAuthTypes).intersection(set(packet.METHODS)))
                                if len(mutual) == 0:
                                        self.log(logging.INFO,'No common authentication types! Client supports %s' % (','.join([str(x) for x in packet.METHODS])), session)
                                        transport.write(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).toBytes())
                                        transport.close()

                                #selecting preferred auth type
                                for authType in self.supportedAuthTypes:
                                        if session.mutualAuthType is not None:
                                                break
                                        
                                        for clientAuthType in mutual:
                                                if authType == clientAuthType:
                                                        session.mutualAuthType = authType
                                                        session.authHandler = SOCKS5AuthHandler(session.mutualAuthType, self.creds)
                                                        break

                                if session.mutualAuthType == SOCKS5Method.NOAUTH:
                                        session.currentState = SOCKS5ServerState.REQUEST #if no authentication is requred then we skip the auth part
                                else:
                                        session.currentState = SOCKS5ServerState.NOT_AUTHENTICATED

                                transport.write(SOCKS5NegoReply.construct(session.mutualAuthType).toBytes())

                        elif session.currentState == SOCKS5ServerState.NOT_AUTHENTICATED:
                                if session.mutualAuthType == SOCKS5Method.PLAIN:
                                        status, creds = session.authHandler.do_AUTH(packet)
                                        if status:
                                                session.currentState = SOCKS5ServerState.REQUEST
                                                transport.write(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOAUTH).toBytes())
                                        else:
                                                transport.write(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).toBytes())
                                                transport.close()
                                else:
                                        #put GSSAPI implementation here
                                        transport.close()
                                        raise Exception('Not implemented!')

                                self.logResult(session, creds.toResult())



                        elif session.currentState == SOCKS5ServerState.REQUEST:
                                self.log(logging.INFO, 'Remote client wants to connect to %s:%d' % (str(packet.DST_ADDR), packet.DST_PORT), session)
                                if packet.CMD == SOCKS5Command.CONNECT:
                                        if self.proxyMode == SOCKS5ServerMode.OFF:
                                                #so long and thanks for all the fish...
                                                transport.close() 
                                        elif self.proxyMode == SOCKS5ServerMode.NORMAL:
                                                #in this case the server acts as a normal socks5 server
                                                #t = threading.Thread(target=self.start_proxy, args=(str(packet.DST_ADDR), packet.DST_PORT, transport, session))
                                                #t.start()
                                                #self.start_proxy(str(packet.DST_ADDR), packet.DST_PORT, transport, session)
                                                task = self.loop.ensure_future(create_clinet_connection(str(packet.DST_ADDR), packet.DST_PORT, transport, session, self))
                                                #asyncio.wait([task], return_when=asyncio.ALL_COMPLETED)
                                                print(task.result())

                                                session.currentState = SOCKS5ServerState.RELAYING
                                                transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.allinterface, 0).toBytes())

                                        else:
                                                #in this case we route the traffic to a specific server :)
                                                fake_dest_ip, fake_dest_port = self.fake_dest_lookup(str(packet.DST_ADDR), packet.DST_PORT)
                                                if fake_dest_ip is None:
                                                        self.log( logging.INFO,'Could not find fake address for %s:%d' % (str(packet.DST_ADDR), packet.DST_PORT), session)
                                                        transport.close()

                                                else:
                                                        #t = threading.Thread(target=self.start_proxy, args=(fake_dest_ip, fake_dest_port, transport, session))
                                                        #t.start()
                                                        #self.start_proxy(fake_dest_ip, fake_dest_port, transport, session)
                                                        task = self.loop.ensure_future(create_clinet_connection(fake_dest_ip, fake_dest_port, transport, session, self))
                                                        asyncio.wait([task])
                                                        session.currentState = SOCKS5ServerState.RELAYING
                                                        transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.allinterface, 0).toBytes())

                                else:
                                        transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.COMMAND_NOT_SUPPORTED, self.allinterface, 0).toBytes())
                                        transport.close()



                except Exception as e:
                        traceback.print_exc()
                        self.log(logging.INFO,'Exception! %s' % (str(e),), session)
                        pass

