import os
import sys
import socket
import struct
import asyncio
import ipaddress
import traceback


from responder3.core.commons import *
from responder3.core.udpwrapper import UDPServer
from responder3.protocols.DHCP import *


class DHCPClient():
        def __init__(self):
                self._query_TID = os.urandom(4)
                self._soc = None
                self._server_coro = None
                self._loop    = asyncio.get_event_loop()
                self.result = {}

        def setup_socket(self):
                self._soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                self._soc.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
                self._soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._soc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self._soc.bind(('', 68))


        def create_server(self):
                self._server = UDPServer(self.listen_responses, None, socket = self._soc)
                self._server_coro = self._server.run()

        def send_discover(self, options_extra = None):
                options = [DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPDISCOVER)]
                if options_extra is not None:
                        options += options_extra
                options.append(DHCPOptEND.construct())
                dhcpquery = DHCPMessage.construct(self._query_TID, DHCPOpcode.BOOTREQUEST, options)
                self._soc.sendto(dhcpquery.toBytes(), ('255.255.255.255', 67))

        @asyncio.coroutine
        def stop_loop(self):
                yield from asyncio.sleep(1)
                self._loop.stop()
                return

        def run(self, options = None):
                self.setup_socket()
                self.create_server()
                self.send_discover(options)

                self._loop.create_task(self.stop_loop())
                try:
                        self._loop.run_until_complete(self._server_coro)
                except RuntimeError as e:
                        if str(e) == 'Event loop stopped before Future completed.':
                                pass
                        else:
                                raise(e)
                except Exception as e:
                        traceback.print_exc()
                        print(e)
                
        def listen_responses(self, reader, writer):
                msg = DHCPMessage.from_buffer(reader.buff)
                if msg.xid == self._query_TID:
                        for option in msg.options:
                                if option.code == 53 and option.msgtype == DHCPOptMessageType.DHCPOFFER:
                                        print('Got offer! IP address offered: %s' % (str(msg.yiaddr)))
                                        print(repr(msg))
                                        self._loop.create_task(self.send_request(msg))

                                if option.code == 53 and option.msgtype == DHCPOptMessageType.DHCPACK:
                                        print('Got ACK!: %s' % (str(msg.yiaddr)))
                                        print(repr(msg))
                                        #self._loop.create_task(self.send_request(msg))

                else:
                        #not a message for us
                        pass

        @asyncio.coroutine
        def send_request(self, offer, request_options_extra = None):
                options = [DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPREQUEST)]
                options.append(DHCPOptREQUESTEDIPADDRESS.construct(offer.yiaddr))
                options.append(DHCPOptSERVERIDENTIFIER.construct(offer.siaddr))
                options.append(DHCPOptPARAMETERREQUEST.construct(list(range(2,61))))
                if request_options_extra is not None:
                        options += request_options_extra
                options.append(DHCPOptEND.construct())
                dhcprequest = DHCPMessage.construct(self._query_TID, DHCPOpcode.BOOTREQUEST, options)
                self._soc.sendto(dhcprequest.toBytes(), ('255.255.255.255', 67))



def main():
        import argparse
        parser = argparse.ArgumentParser(description = 'DHCP client. Requests an IP address from the DHCP server')
        parser.add_argument("-t", dest='timeout', default=1, help="Time to wait for responses")
        args = parser.parse_args()

        client = DHCPClient()
        client.run()

if __name__ == '__main__':
        main()