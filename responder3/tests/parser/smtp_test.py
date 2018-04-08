#!/usr/bin/env python3.6

from responder3.protocols.SMTP import *


def parse_comm(comms):
	is_multiline = False
	multiline_buffer = b''
	is_multiline_reply = False
	multiline_buffer_reply = b''
	p = SMTPCommandParser()
	r = SMTPResponseParser()
	for direction, comm in comms:
		print(comm)
		if direction == 'S':
			t = comm.decode()
			if is_multiline_reply:
				if t[3] == ' ':
					multiline_buffer_reply += comm
					e = r.from_bytes(multiline_buffer_reply)

			if t[3] == '-':
				is_multiline_reply = True
				multiline_buffer_reply += comm
			else:
				if is_multiline_reply:
					is_multiline_reply = False
					e = r.from_bytes(multiline_buffer_reply)
					multiline_buffer_reply = b''
				else:
					e = r.from_bytes(comm)

				if not is_multiline_reply:
					print(type(e))
					print(str(e.parameter))
					input()

		else:
			t = comm.decode()
			if t[:4] == 'DATA':
				is_multiline = True
				multiline_buffer += comm
				continue

			if is_multiline:
				multiline_buffer += comm
				if t == '.\r\n':
					is_multiline = False
					e = p.from_bytes(multiline_buffer)
					print(type(e))
					print(str(e))
					input()

			else:
				e = p.from_bytes(comm)

				print(type(e))
				print(str(e))
				input()


comms = [
	('S', b'220 foo.com Simple Mail Transfer Service Ready\r\n'),
	('C', b'EHLO bar.com\r\n'),
	('S', b'250-foo.com greets bar.com\r\n'),
	('S', b'250-8BITMIME\r\n'),
	('S', b'250-SIZE\r\n'),
	('S', b'250-DSN\r\n'),
	('S', b'250 HELP\r\n'),
	('C', b'MAIL FROM:<Smith@bar.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'RCPT TO:<Jones@foo.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'RCPT TO:<Green@foo.com>\r\n'),
	('S', b'550 No such user here\r\n'),
	('C', b'RCPT TO:<Brown@foo.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'DATA\r\n'),
	('S', b'354 Start mail input; end with <CRLF>.<CRLF>\r\n'),
	('C', b'HELLO!!\r\n'),
	('C', b'.\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'QUIT\r\n'),
	('S', b'221 foo.com Service closing transmission channel\r\n'),
]

comms2 = [
	('S', b'220 foo.com Simple Mail Transfer Service Ready\r\n'),
	('C', b'EHLO bar.com\r\n'),
	('S', b'250-foo.com greets bar.com\r\n'),
	('S', b'250-8BITMIME\r\n'),
	('S', b'250-SIZE\r\n'),
	('S', b'250-DSN\r\n'),
	('S', b'250 HELP\r\n'),
	('C', b'MAIL FROM:<Smith@bar.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'RCPT TO:<Jones@foo.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'RCPT TO:<Green@foo.com>\r\n'),
	('S', b'550 No such user here\r\n'),
	('C', b'RSET\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'QUIT\r\n'),
	('S', b'221 foo.com Service closing transmission channel\r\n'),
]

comms3 = [
	('S', b'220 foo.com Simple Mail Transfer Service Ready\r\n'),
	('C', b'EHLO bar.com\r\n'),
	('S', b'250-foo.com greets bar.com\r\n'),
	('S', b'250-8BITMIME\r\n'),
	('S', b'250-SIZE\r\n'),
	('S', b'250-DSN\r\n'),
	('S', b'250-VRFY\r\n'),
	('S', b'250 HELP\r\n'),
	('C', b'VRFY Crispin\r\n'),
	('S', b'250 Mark Crispin <Admin.MRC@foo.com>\r\n'),
	('C', b'MAIL FROM:<EAK@bar.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'RCPT TO:<Admin.MRC@foo.com>\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'DATA\r\n'),
	('S', b'354 Start mail input; end with <CRLF>.<CRLF>\r\n'),
	('C', b'Blah blah blah...\r\n'),
	('C', b'...etc. etc. etc.\r\n'),
	('C', b'.\r\n'),
	('S', b'250 OK\r\n'),
	('C', b'QUIT\r\n'),
	('S', b'221 foo.com Service closing transmission channel\r\n'),
]

parse_comm(comms)
parse_comm(comms2)
parse_comm(comms3)
