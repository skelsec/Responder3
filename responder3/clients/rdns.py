import asyncio
import ipaddress

from responder3.protocols.DNS import *
from responder3.core.udpwrapper import UDPClient
import os

class RDNS:
	def __init__(self, server = '8.8.8.8', protocol = 'TCP'):
		self.server = server
		self.protocol = protocol
		
	
	async def resolve(self, ip):
		try:
			ip = ipaddress.ip_address(ip).reverse_pointer
			tid = os.urandom(2)
			question = DNSQuestion.construct(ip, DNSType.PTR, DNSClass.IN, qu = False)
				
						
			if self.protocol == 'TCP':
				packet = DNSPacket.construct(
							TID = tid, 
							flags = DNSFlags.RD,
							response = DNSResponse.REQUEST, 
							opcode = DNSOpcode.QUERY, 
							rcode = DNSResponseCode.NOERR, 
							questions= [question], 
							proto = socket.SOCK_STREAM
						)
				reader, writer = await asyncio.open_connection(self.server, 53)
				writer.write(packet.to_bytes())
				await writer.drain()
				
				data = await DNSPacket.from_streamreader(reader, proto = socket.SOCK_STREAM)
				print(data.Answers[0].domainname)
				return data.Answers[0].domainname
			else:
				cli = UDPClient((self.server, 53))
				
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
				print(data.Answers[0].domainname)
				return data.Answers[0].domainname
		
		except Exception as e:
			return None
			
			
					
					
if __name__ == '__main__':
	resolver = RDNS(protocol = 'TCP')
	
	ip = '130.211.198.204'
	
	loop = asyncio.get_event_loop()
	loop.run_until_complete(resolver.resolve(ip))
	loop.close()