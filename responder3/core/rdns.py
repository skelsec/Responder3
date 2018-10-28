import ipaddress
from responder3.protocols.DNS import *
from responder3.core.udpwrapper import UDPClient
import os

#, resolver_server = '8.8.8.8', resolver_server_6 = '2001:4860:4860::8888'

# TODO: make use of all servers in the list, not just the first one
# TODO: enable IPv6

class RDNS:
	def __init__(self, server, server6):
		self.server = server #list of dict [{'ip':'8.8.8.8', 'port':53, 'proto' : 'udp'}]
		self.server6 = server6 #not used yet #list of dict  [{ 'ip': '2001:4860:4860::8888', 'port':53, 'proto' : 'udp'}]
		
	
	async def resolve(self, ip):
		try:
			ip = ipaddress.ip_address(ip).reverse_pointer
			tid = os.urandom(2)
			question = DNSQuestion.construct(ip, DNSType.PTR, DNSClass.IN, qu = False)
				
						
			if self.server[0]['proto'].upper() == 'TCP':
				packet = DNSPacket.construct(
							TID = tid, 
							flags = DNSFlags.RD,
							response = DNSResponse.REQUEST, 
							opcode = DNSOpcode.QUERY, 
							rcode = DNSResponseCode.NOERR, 
							questions= [question], 
							proto = socket.SOCK_STREAM
						)
				reader, writer = await asyncio.open_connection(self.server[0]['ip'], self.server[0]['port'])
				writer.write(packet.to_bytes())
				await writer.drain()
				
				data = await DNSPacket.from_streamreader(reader, proto = socket.SOCK_STREAM)
				return data.Answers[0].domainname
			else:
				cli = UDPClient((self.server[0]['ip'], self.server[0]['port']))
				
				packet = DNSPacket.construct(
							TID = tid, 
							flags = DNSFlags.RD,
							response = DNSResponse.REQUEST, 
							opcode = DNSOpcode.QUERY, 
							rcode = DNSResponseCode.NOERR, 
							questions= [question], 
							proto = socket.SOCK_DGRAM
						)
						
				reader, writer = await cli.run(packet.to_bytes())	
				data = await DNSPacket.from_streamreader(reader)
				return data.Answers[0].domainname
		
		except Exception as e:
			return None