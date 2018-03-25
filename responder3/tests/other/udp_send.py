import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
sock.setsockopt(socket.SOL_SOCKET, 25, 'ens37\0'.encode())
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(('0.0.0.0', 67)) #only IPv4 is supported, because IPv6 packs it's own DHCP protocol, which is completely different

sock.sendto(b'AAAAAAAAAAAA', ('192.168.111.1', 500))