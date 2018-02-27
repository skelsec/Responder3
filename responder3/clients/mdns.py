import os
import sys
import socket
import struct
import asyncio
import ipaddress
import traceback


from responder3.core.commons import *
from responder3.core.udpwrapper import UDPServer
from responder3.protocols.DNS import *


class MDNSClient():
        def __init__(self, timeout = 5):
                self._mcast_addr = ('224.0.0.251', 5353)
                self.timeout = timeout
                self._query_names = {}
                self._soc = None
                self._server_coro = None
                self._query_packet = None
                self._loop    = asyncio.get_event_loop()
                self.result = {}

        def setup_socket(self):
                mcast_addr = ipaddress.ip_address(self._mcast_addr[0])
                self._soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                self._soc.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
                self._soc.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                self._soc.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                self._soc.bind(self._mcast_addr)
                mreq = struct.pack("=4sl", mcast_addr.packed, socket.INADDR_ANY)
                self._soc.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        def create_server(self):
                self._server = UDPServer(self.listen_responses, None, socket = self._soc)
                self._server_coro = self._server.run()

        def send_queries(self, query_names):
                qstns = []
                for qry in query_names:
                        for dtype in [DNSType.A, DNSType.AAAA]:
                                if qry.find('.local') == -1:
                                        qry += '.local'
                                qstns.append(DNSQuestion.construct(qry, dtype, DNSClass.IN))

                                tid = os.urandom(2)
                                if qry not in self._query_names: #apparently there are no transaction IDs in mdns...
                                        self._query_names[qry] = 1
                                self._query_packet = DNSPacket.construct(TID = tid, 
                                                                                                                 response  = DNSResponse.REQUEST, 
                                                                                                                 questions = qstns)

                                self._soc.sendto(self._query_packet.toBytes(), self._mcast_addr)

        @asyncio.coroutine
        def stop_loop(self):
                yield from asyncio.sleep(self.timeout)
                self._loop.stop()
                return

        def run(self, query_names):
                self.setup_socket()
                self.create_server()
                self.send_queries(query_names)

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
                
                return self.result


                
        def listen_responses(self, reader, writer):
                msg = DNSPacket.from_buffer(reader.buff)
                if msg.QR == DNSResponse.RESPONSE:
                        for ans in msg.Answers:
                                if ans.TYPE == DNSType.A or ans.TYPE == DNSType.AAAA:
                                        if ans.NAME.name in self._query_names:
                                                if ans.NAME.name not in self.result:
                                                        self.result[ans.NAME.name] = []
                                                self.result[ans.NAME.name].append(ans.ipaddress)


def main():
        import argparse
        parser = argparse.ArgumentParser(description = 'Enumerates all devices on the network which has registered with Bonjour service')
        parser.add_argument("-t", type=int, default = 5, help="timeout for waiting services to reply")
        parser.add_argument("-q", nargs='+', help="DNS name")

        args = parser.parse_args()
        queries = args.q

        client = MDNSClient(args.t)
        res = client.run(queries)
        print(res)

if __name__ == '__main__':
        main()