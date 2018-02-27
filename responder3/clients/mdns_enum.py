import os
import sys
import socket
import struct
import asyncio
import ipaddress


from responder3.core.commons import *
from responder3.core.udpwrapper import UDPServer
from responder3.protocols.DNS import *


class MDNSClient():
        def __init__(self, timeout = 5):
                self._mcast_addr = ('224.0.0.251', 5353)
                self.timeout = timeout
                self._query_TID = os.urandom(2)
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
                        qstns.append(DNSQuestion.construct(qry, DNSType.PTR, DNSClass.IN))


                self._query_packet = DNSPacket.construct(TID = self._query_TID, 
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
                                if ans.domainname.name[0] == '_':
                                        #walking the tree...
                                        print('Walk the tree: %s' % ans.domainname.name)
                                        qst = DNSQuestion.construct(ans.domainname.name, DNSType.PTR, DNSClass.IN)
                                        qry = DNSPacket.construct(TID = os.urandom(2), 
                                                                                                         response  = DNSResponse.REQUEST, 
                                                                                                         questions = [qst])
                                        self._soc.sendto(qry.toBytes(), self._mcast_addr)

                                #else:
                                #        print(ans.domainname)

                        name = None
                        for ans in msg.Additionals:
                                if ans.TYPE == DNSType.A or ans.TYPE == DNSType.AAAA:
                                        if ans.NAME.name not in self.result:
                                                self.result[ans.NAME.name] = {}
                                        self.result[ans.NAME.name][ans.ipaddress] = []
                                        name = ans.NAME.name

                        for ans in msg.Additionals:
                                if ans.TYPE == DNSType.SRV:
                                        for ip in self.result[name]:
                                                self.result[name][ip].append(ans.Port)


def main():
        import argparse
        parser = argparse.ArgumentParser(description = 'Enumerates all devices on the network which has registered with Bonjour service')
        parser.add_argument("-t", type=int, default = 5, help="timeout for waiting services to reply")

        args = parser.parse_args()
        queries = []
        queries.append('_services._dns-sd._udp.local')

        client = MDNSClient(args.t)
        res = client.run(queries)
        for name in res:
                for address in res[name]:
                        for port in res[name][address]:
                                print('%s has the address of %s, advertising port %s' % (name, str(address), port ))

if __name__ == '__main__':
        main()