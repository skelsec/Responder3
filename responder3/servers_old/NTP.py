"""
TODO:
1. broadcast NTP
2. TCP NTP
3. cleanup
4. implement peer command reply
5. implement and capute authentication
... a lot of things :(
"""

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
import datetime

from responder3.utils import ServerProtocol
from responder3.protocols.NTP import * 
from responder3.core.servertemplate import ResponderServer, ResponderProtocolUDP, ResponderProtocolTCP, ProtocolSession

class NTPSession(ProtocolSession):
        def __init__(self):
                ProtocolSession.__init__(self)
                self._parsed_length = None

class NTP(ResponderServer):
        def __init__(self):
                ResponderServer.__init__(self)
                #self.refID = ipaddress.IPv4Address(os.urandom(4))

        def modulename(self):
                return 'NTP'

        def setup(self):
                self.protocol = NTPProtocolUDP
                ###### DEFAULT SETTINGS
                self.refID = ipaddress.IPv4Address('127.0.0.1')
                self.fakeTime = datetime.datetime.now()
                fmt = '%b %d %Y %H:%M'
                ###### PARSING SETTINGS IF ANY
                if self.settings is None:
                        return

                if 'refID' in self.settings:
                        self.refID = ipaddress.ip_address(self.settings['refID'])

                if 'fakeTime' in self.settings:                        
                        if 'fakeTimeFmt' in self.settings:
                                fmt = self.settings['fakeTimeFmt']
                        
                        self.fakeTime = datetime.datetime.strptime(self.settings['fakeTime'], fmt)
                #if self.bind_proto == ServerProtocol.TCP:
                #        self.protocol = NTPProtocolTCP

        def handle(self, packet, addr, transport, session):
                if 'R3DEEPDEBUG' in os.environ:
                        self.log(logging.INFO,'Packet: %s' % (repr(packet),), session)
                try:
                        self.log(logging.INFO,'Request in! Spoofing time to: %s' % self.fakeTime.isoformat(), session)
                        transport.sendto(NTPPacket.construct_fake_reply(packet.TransmitTimestamp, self.fakeTime, self.refID).toBytes(), addr)

                except Exception as e:
                        traceback.print_exc()
                        self.log(logging.INFO,'Exception! %s' % (str(e),))
                        pass


class NTPProtocolUDP(ResponderProtocolUDP):
        
        def __init__(self, server):
                ResponderProtocolUDP.__init__(self, server)
                self._session = NTPSession()

        def _parsebuff(self, addr):
                packet = NTPPacket.from_bytes(self._buffer, ServerProtocol.UDP)
                self._server.handle(packet, addr, self._transport, self._session)
                self._buffer = b''


"""
class NTPProtocolTCP(ResponderProtocolTCP):
        
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
"""
