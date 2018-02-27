import io
import os
import re
import logging
import traceback
import socket
import struct
import enum
import traceback
import ipaddress

from responder3.utils import ServerProtocol
from responder3.protocols.DNS import * 
from responder3.core.servertemplate import ResponderServer, ResponderProtocolUDP, ResponderProtocolTCP, ProtocolSession, PoisonerMode

class DNSSession(ProtocolSession):
        def __init__(self):
                ProtocolSession.__init__(self)
                self._parsed_length = None

class DNS(ResponderServer):
        def __init__(self):
                ResponderServer.__init__(self)

        def modulename(self):
                return 'DNS'

        def setup(self):
                self.protocol = DNSProtocolUDP
                if self.bind_proto == ServerProtocol.TCP:
                        self.protocol = DNSProtocolTCP

                self.spoofTable = []
                self.passthru = False
                if 'passthru' in self.settings and self.settings['passthru']:
                        self.passthru = True
                        if self.settings['passthru']['dnsserver'].find(':'):
                                self.passthru_server, self.passthru_port = self.settings['passthru']['dnsserver'].split(':')
                                self.passthru_port = int(self.passthru_port)
                        
                        else:
                                self.passthru_server = self.settings['passthru']['dnsserver']
                                self.passthru_port   = 53
                        
                        self.passthru_ip     = self.settings['passthru']['bindIP'] if 'bindIP' in self.settings['passthru'] else ''
                
                if self.settings is None:
                        self.log(logging.INFO, 'No settings defined, adjusting to Analysis functionality!')
                        self.settings = {}
                        self.settings['mode'] = PoisonerMode.ANALYSE

                else:
                        #parse the poisoner mode
                        if isinstance(self.settings['mode'], str):
                                self.settings['mode'] = PoisonerMode[self.settings['mode'].upper()]

                        #compiling re strings to actual re objects and converting IP strings to IP objects
                        if self.settings['mode'] == PoisonerMode.SPOOF:
                                for exp in self.settings['spoofTable']:
                                        if exp == 'ALL':
                                                self.spoofTable.append((re.compile('.*'),ipaddress.ip_address(self.settings['spoofTable'][exp])))
                                                continue
                                        self.spoofTable.append((re.compile(exp),ipaddress.ip_address(self.settings['spoofTable'][exp])))

        

        def handle(self, packet, addr, transport, session):
                if 'R3DEEPDEBUG' in os.environ:
                                self.log(logging.INFO,'Packet: %s' % (repr(packet),), session)
                try:
                        if self.settings['mode'] == PoisonerMode.ANALYSE:
                                for q in packet.Questions:
                                        self.logPoisonResult(session, requestName = q.QNAME.name)

                        else:
                                answers = []
                                for targetRE, ip in self.spoofTable:
                                        for q in packet.Questions:
                                                if targetRE.match(q.QNAME.name):
                                                        self.logPoisonResult(session, requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
                                                        if ip.version == 4:
                                                                res = DNSAResource.construct(q.QNAME.name, ip)
                                                        elif ip.version == 6:
                                                                res = DNSAAAAResource.construct(q.QNAME.name, ip)
                                                        else:
                                                                raise Exception('This IP version scares me...')
                                                        #res.construct(q.QNAME, NBRType.NB, ip)
                                                        answers.append(res)
                                                
                                                elif self.passthru:
                                                        #if ANY of the query names requested doesnt match our spoof table, then we ask an actual DNS server
                                                        #this completely overrides any match from the spooftable!
                                                        if self.bind_proto == ServerProtocol.UDP:
                                                                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                sock.bind((self.passthru_ip, 0))
                                                                sock.sendto(packet.toBytes(), (self.passthru_server, self.passthru_port))
                                                                data, dns_server_addr = sock.recvfrom(1024)
                                                                passthru_packet = DNSPacket.from_bytes(data, self.bind_proto)
                                                                self.log(logging.INFO,'Passthru packet recieved! %s' % (repr(passthru_packet),))
                                                                #do modification if you wish here
                                                                #passthru_packet << this will be sent back to the victim
                                                                transport.sendto(passthru_packet.toBytes(), addr)
                                                                return

                                                        else:
                                                                ### THIS IS A QUICK HACK!!! SOCK.RECV SHOULDN'T BE USED LIKE THIS
                                                                ### make asyncio!!
                                                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                                sock.bind((self.passthru_ip, 0))
                                                                sock.connect((self.passthru_server, self.passthru_port))
                                                                sock.sendall(packet.toBytes())
                                                                data = sock.recv(1024)
                                                                passthru_packet = DNSPacket.from_bytes(data, self.bind_proto)
                                                                self.log(logging.INFO,'Passthru packet recieved! %s' % (repr(passthru_packet),))
                                                                #do modification if you wish here
                                                                #passthru_packet << this will be sent back to the victim
                                                                transport.write(passthru_packet.toBytes())
                                                                return

                                
                                if len(answers) == 0 :
                                        #DNS error response should be here!
                                        raise Exception('DNS error response should be here!')
                                        return

                                response = DNSPacket.construct(TID = packet.TransactionID, 
                                                                                                 response = DNSResponse.RESPONSE, 
                                                                                                 answers = answers,
                                                                                                 questions = packet.Questions,
                                                                                                 proto = self.bind_proto)


                                if self.bind_proto == ServerProtocol.UDP:
                                        transport.sendto(response.toBytes(), addr)
                                else:
                                        transport.write(response.toBytes())

                        
                        

                except Exception as e:
                        traceback.print_exc()
                        self.log(logging.INFO,'Exception! %s' % (str(e),))
                        pass


class DNSProtocolUDP(ResponderProtocolUDP):
        
        def __init__(self, server):
                ResponderProtocolUDP.__init__(self, server)
                self._session = DNSSession()

        def _parsebuff(self, addr):
                packet = DNSPacket.from_bytes(self._buffer, ServerProtocol.UDP)
                self._server.handle(packet, addr, self._transport, self._session)
                self._buffer = b''


class DNSProtocolTCP(ResponderProtocolTCP):
        
        def __init__(self, server):
                ResponderProtocolTCP.__init__(self, server)
                self._session = DNSSession(server.rdnsd)
                        
                
        def _parsebuff(self):
                if self._session._parsed_length is None and len(self._buffer) > 2:
                        self._session._parsed_length = int.from_bytes(self._buffer[:2], byteorder = 'big', signed=False)

                if len(self._buffer) >= self._session._parsed_length:
                        packet = DNSPacket.from_bytes(self._buffer[:self._session._parsed_length + 2], ServerProtocol.TCP)
                        self._server.handle(packet, None, self._transport, self._session)
                        self._buffer = self._buffer[self._session._parsed_length + 2:]
                        self._session._parsed_length = None
                        if len(self._buffer) != 0:
                                self._parsebuff()

