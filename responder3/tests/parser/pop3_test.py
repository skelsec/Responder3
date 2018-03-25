from responder3.protocols.POP3 import *


def parse_comm(comms):
	p = POP3CommandParser()
	r = POP3ResponseParser()
	for direction, comm in comms:
		print(comm)
		if direction == 'C':
			e = p.from_bytes(comm)
		else:
			e = r.from_bytes(comm)
		print(type(e))
		print(str(e))
		input()


comms = [
	('C', b'QUIT\r\n'),
	('S', b'+OK dewey POP3 server signing off\r\n'),
	('C', b'STAT\r\n'),
	('S', b'+OK 2 320\r\n'),
	('C', b'LIST\r\n'),
	('S', b'+OK 2 messages (320 octets)\r\n'),
	('S', b'1 120\r\n'),
	('S', b'2 200\r\n'),
	('S', b'.\r\n'),
	('C', b'LIST 2\r\n'),
	('S', b'+OK 2 200\r\n'),
	('C', b'LIST 3\r\n'),
	('S', b'-ERR no such message, only 2 messages in maildrop\r\n'),
	('C', b'RETR 1\r\n'),
	('S', b'+OK 120 octets\r\n'),
	('S', b'<the POP3 server sends the entire message here>\r\n'),
	('S', b'.\r\n'),
	('C', b'DELE 1\r\n'),
	('S', b'+OK message 1 deleted\r\n'),
	('C', b'DELE 2\r\n'),
	('S', b'-ERR message 2 already deleted\r\n'),
	('C', b'NOOP\r\n'),
	('S', b'+OK\r\n'),
	('C', b'RSET\r\n'),
	('S', b'+OK maildrop has 2 messages (320 octets)\r\n'),
	('C', b'QUIT\r\n'),
	('S', b'+OK dewey POP3 server signing off (maildrop empty)\r\n'),
	('C', b'QUIT\r\n'),
	('S', b'+OK dewey POP3 server signing off (2 messages left)\r\n'),
	('C', b'TOP 1 10\r\n'),
	('S', b'+OK\r\n'),
	('C', b'TOP 100 3\r\n'),
	('S', b'-ERR no such message\r\n'),
	('C', b'UIDL\r\n'),
	('S', b'+OK\r\n'),
	('S', b'1 whqtswO00WBw418f9t5JxYwZ\r\n'),
	('S', b'2 QhdPYR:00WBw1Ph7x7\r\n'),
	('S', b'.\r\n'),
	('C', b'UIDL 2\r\n'),
	('S', b'+OK 2 QhdPYR:00WBw1Ph7x7\r\n'),
	('C', b'UIDL 3\r\n'),
	('S', b'-ERR no such message, only 2 messages in maildrop\r\n'),
	('C', b'USER frated\r\n'),
	('S', b'-ERR sorry, no mailbox for frated here\r\n'),
	('C', b'USER mrose\r\n'),
	('S', b'+OK mrose is a real hoopy frood\r\n'),
	('C', b'USER mrose\r\n'),
	('S', b'+OK mrose is a real hoopy frood\r\n'),
	('C', b'PASS secret\r\n'),
	('S', b'-ERR maildrop already locked\r\n'),
	('C', b'USER mrose\r\n'),
	('S', b'+OK mrose is a real hoopy frood\r\n'),
	('C', b'PASS secret\r\n'),
	('S', b'+OK mrose\'s maildrop has 2 messages (320 octets)\r\n'),
	('S', b'+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n'),
	('C', b'APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n'),
	('S', b'+OK maildrop has 1 message (369 octets)\r\n'),
	('S', b'+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n'),
	('C', b'APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n'),
	('S', b'+OK mrose\'s maildrop has 2 messages (320 octets)\r\n'),
	('C', b'STAT\r\n'),
	('S', b'+OK 2 320\r\n'),
	('C', b'LIST\r\n'),
	('S', b'+OK 2 messages (320 octets)\r\n'),
	('S', b'1 120\r\n'),
	('S', b'2 200\r\n'),
	('S', b'.\r\n'),
	('C', b'RETR 1\r\n'),
	('S', b'+OK 120 octets\r\n'),
	('S', b'.\r\n'),
	('C', b'DELE 1\r\n'),
	('S', b'+OK message 1 deleted\r\n'),
	('C', b'RETR 2\r\n'),
	('S', b'+OK 200 octets\r\n'),
	('S', b'.\r\n'),
	('C', b'DELE 2\r\n'),
	('S', b'+OK message 2 deleted\r\n'),
	('C', b'QUIT\r\n'),
	('S', b'+OK dewey POP3 server signing off (maildrop empty)\r\n'),
]

parse_comm(comms)

