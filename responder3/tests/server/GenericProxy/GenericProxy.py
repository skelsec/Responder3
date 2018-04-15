#!/usr/bin/env python3.6
from responder3.core.test_helper import setup_test
from responder3.core.sockets import setup_base_socket
from responder3.core.interfaceutil import interfaces
import threading
import socket
import time
import ssl

r3, global_config = setup_test(__file__)
r3_process = r3.start_process()

testdata = b'HELLO!\n'
test_cases = [
	('127.0.0.1', 6666, socket.SOCK_STREAM, False),
	('127.0.0.1', 6667, socket.SOCK_STREAM, True),
	('127.0.0.1', 6668, socket.SOCK_STREAM, True),
	('127.0.0.1', 6669, socket.SOCK_DGRAM, False),
	('127.0.0.1', 6670, socket.SOCK_STREAM, False),
]

def echo_server(ip, port, protocol, is_ssl = None):
	server_socket = setup_base_socket(interfaces.get_socketconfig_from_ip('127.0.0.1', port, protocol))
	server_socket.setblocking(True)
	if protocol == socket.SOCK_STREAM:
		if is_ssl:
			context = ssl.SSLContext()
			context.verify_mode = ssl.CERT_NONE
			context.load_cert_chain(
				certfile='../testcert/responder3.crt',
				keyfile ='../testcert/responder3.key'
			)
			server_socket = context.wrap_socket(server_socket, server_side = True)

		server_socket.listen(5)
		while True:
			# accept connections from outside
			(clientsocket, address) = server_socket.accept()
			# now do something with the clientsocket
			# in this case, we'll pretend this is a threaded server
			data = clientsocket.recv(1024)
			print(data)
			clientsocket.sendall(data)
	else:
		while True:
			data, addr = server_socket.recvfrom(1024)
			print(data)
			server_socket.sendto(data, addr)


print('Setting up servers')
for test_case in test_cases:
	t = threading.Thread(target=echo_server, args=test_case)
	t.daemon = True
	t.start()

time.sleep(1)

# Test1
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('127.0.0.1', 5555))
	s.sendall(testdata)
	data = s.recv(1024)
	print(data)
	assert data == testdata
	print('[+] Test case 1 SUCCESS')
except Exception as e:
	print('[-] Test case 1 FAILED. Reason: %s' % e)

# Test 2
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s = ssl.wrap_socket(s, server_side=False)
	s.connect(('127.0.0.1', 5556))
	s.sendall(testdata)
	data = s.recv(1024)
	print(data)
	assert data == testdata
	print('[+] Test case 2 SUCCESS')
except Exception as e:
	print('[-] Test case 2 FAILED. Reason: %s' % e)

# Test 3
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s = ssl.wrap_socket(s, server_side=False)
	s.connect(('127.0.0.1', 5557))
	s.sendall(testdata)
	data = s.recv(1024)
	print(data)
	assert data == testdata
	print('[+] Test case 3 SUCCESS')
except Exception as e:
	print('[-] Test case 3 FAILED. Reason: %s' % e)

# Test 4
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.sendto(testdata, ('127.0.0.1', 5558))
	data, addr = s.recvfrom(1024)
	print(data)
	assert data == testdata
	print('[+] Test case 4 SUCCESS')
except Exception as e:
	print('[-] Test case 4 FAILED. Reason: %s' % e)

# Test 5
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s = ssl.wrap_socket(s, server_side=False)
	s.connect(('127.0.0.1', 5559))
	s.sendall(testdata)
	data = s.recv(1024)
	print(data)
	assert data == testdata
	print('[+] Test case 5 SUCCESS')
except Exception as e:
	print('[-] Test case 5 FAILED. Reason: %s' % e)

r3_process.join()