import socket
import struct
import logging
import asyncio
import ipaddress

from responder3.core.commons import *
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.protocols.DNS import *


class MDNSSession(ResponderServerSession):
        pass

class MDNS(ResponderServer):
        def custom_socket(server_properties):
                mcast_addr = ipaddress.ip_address('224.0.0.251')
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                sock.bind((str(mcast_addr), server_properties.bind_port))
                mreq = struct.pack("=4sl", mcast_addr.packed, socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                return sock

        def init(self):
                self.parser = DNSPacket
                self.spoofTable = []
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

        @asyncio.coroutine
        def parse_message(self):
                yield from self.parser.from_streamreader(self.creader)
        
        
        @asyncio.coroutine
        def run(self):
                print('HERE!')
                """
                try:
                        msg = asyncio.wait_for(self.parse_message(), timeout=1)
                        print(repr(msg))
                        if msg.QR == DNSResponse.REQUEST:
                                if self.settings['mode'] == PoisonerMode.ANALYSE:
                                        for q in msg.Questions:
                                                self.logPoisonResult(session, requestName = q.QNAME.name)

                                else:
                                        answers = []
                                        for targetRE, ip in self.spoofTable:
                                                for q in msg.Questions:
                                                        if targetRE.match(q.QNAME.name):
                                                                self.logPoisonResult(session, requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
                                                                #BE AWARE THIS IS NOT CHECKING IF THE QUESTION AS FOR IPV4 OR IPV6!!!
                                                                if ip.version == 4:
                                                                        res = DNSAResource.construct(q.QNAME.name, ip)
                                                                elif ip.version == 6:
                                                                        res = DNSAAAAResource.construct(q.QNAME.name, ip)
                                                                else:
                                                                        raise Exception('This IP version scares me...')
                                                                #res.construct(q.QNAME, NBRType.NB, ip)
                                                                answers.append(res)
                                        
                                        response = DNSPacket.construct(TID = msg.TransactionID, 
                                                                                                         response  = DNSResponse.RESPONSE, 
                                                                                                         answers   = answers,
                                                                                                         questions = msg.Questions)

                                        asyncio.wait_for(self.send_data(response.toBytes()), timeout=1)

                except Exception as e:
                        traceback.print_exc()
                        self.log('Exception! %s' % (str(e),))
                        pass
                """
                
        """
        def handle(self, packet, addr, transport, session):
                if 'R3DEEPDEBUG' in os.environ:
                                self.log(logging.INFO,'Packet: %s' % (repr(packet),), session)
                try:
                        #only care about the requests
                        if packet.QR == DNSResponse.REQUEST:
                                if self.settings['mode'] == PoisonerMode.ANALYSE:
                                        for q in packet.Questions:
                                                self.logPoisonResult(session, requestName = q.QNAME.name)

                                else:
                                        answers = []
                                        for targetRE, ip in self.spoofTable:
                                                for q in packet.Questions:
                                                        if targetRE.match(q.QNAME.name):
                                                                self.logPoisonResult(session, requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
                                                                #BE AWARE THIS IS NOT CHECKING IF THE QUESTION AS FOR IPV4 OR IPV6!!!
                                                                if ip.version == 4:
                                                                        res = DNSAResource.construct(q.QNAME.name, ip)
                                                                elif ip.version == 6:
                                                                        res = DNSAAAAResource.construct(q.QNAME.name, ip)
                                                                else:
                                                                        raise Exception('This IP version scares me...')
                                                                #res.construct(q.QNAME, NBRType.NB, ip)
                                                                answers.append(res)
                                        
                                        response = DNSPacket.construct(TID = packet.TransactionID, 
                                                                                                         response  = DNSResponse.RESPONSE, 
                                                                                                         answers   = answers,
                                                                                                         questions = packet.Questions)

                                        transport.sendto(response.toBytes(), addr)

                        

                except Exception as e:
                        traceback.print_exc()
                        self.log(logging.INFO,'Exception! %s' % (str(e),))
                        pass
        """