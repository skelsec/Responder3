from responder3.protocols.IMAP import *

def parse_comm(comms):
	p = IMAPCommandParser()
	r = IMAPResponseParser()
	for direction, comm in comms:
		print(comm)
		if direction == 'C':
			e = p.from_bytes(comm)
		else:
			e = r.from_bytes(comm)
		print(type(e))
		print(str(e))
		input()

comms1 = [
		('C',b'abcd CAPABILITY\r\n'),
		('S',b'* CAPABILITY IMAP4rev1 STARTTLS AUTH=GSSAPI LOGINDISABLED\r\n'),
		('S',b'abcd OK CAPABILITY completed\r\n'),
		('C',b'efgh STARTTLS\r\n'),
		('S',b'efgh OK STARTLS completed\r\n'),
		('C',b'ijkl CAPABILITY\r\n'),
		('S',b'* CAPABILITY IMAP4rev1 AUTH=GSSAPI AUTH=PLAIN\r\n'),
		('S',b'ijkl OK CAPABILITY completed\r\n'),
]

comms2 = [
	('C',b'a002 NOOP\r\n'),
	('S',b'a002 OK NOOP completed\r\n'),
	('C',b'a047 NOOP\r\n'),
	('S',b'* 22 EXPUNGE\r\n'),
	('S',b'* 23 EXISTS\r\n'),
	('S',b'* 3 RECENT\r\n'),
	('S',b'* 14 FETCH (FLAGS (\Seen \Deleted))\r\n'),
	('S',b'a047 OK NOOP completed\r\n'),
]

comms3 = [
	('C',b'A023 LOGOUT\r\n'),
	('S',b'* BYE IMAP4rev1 Server logging out\r\n'),
	('S',b'A023 OK LOGOUT completed\r\n'),
]

comms4 = [
	('S',b'* OK IMAP4rev1 Server\r\n'),
	('C',b'A001 AUTHENTICATE GSSAPI\r\n'),
	('S',b'+\r\n'),
	('C',b'YIIB+wYJKoZIhvcSAQICAQBuggHqMIIB5qADAgEFoQMCAQ6iBwMFACAAAACjggEmYYIBIjCCAR6gAwIBBaESGxB1Lndhc2hpbmd0b24uZWR1oi0wK6ADAgEDoSQwIhsEaW1hcBsac2hpdmFtcy5jYWMud2FzaGluZ3Rvbi5lZHWjgdMwgdCgAwIBAaEDAgEDooHDBIHAcS1GSa5b+fXnPZNmXB9SjL8Ollj2SKyb+3S0iXMljen/jNkpJXAleKTz6BQPzj8duz8EtoOuNfKgweViyn/9B9bccy1uuAE2HI0yC/PHXNNU9ZrBziJ8Lm0tTNc98kUpjXnHZhsMcz5Mx2GR6dGknbI0iaGcRerMUsWOuBmKKKRmVMMdR9T3EZdpqsBd7jZCNMWotjhivd5zovQlFqQ2Wjc2+y46vKP/iXxWIuQJuDiisyXF0Y8+5GTpALpHDc1/pIGmMIGjoAMCAQGigZsEgZg2on5mSuxoDHEA1w9bcW9nFdFxDKpdrQhVGVRDIzcCMCTzvUboqb5KjY1NJKJsfjRQiBYBdENKfzK+g5DlV8nrw81uOcP8NOQCLR5XkoMHC0Dr/80ziQzbNqhxO6652Npft0LQwJvenwDI13YxpwOdMXzkWZN/XrEqOWp6GCgXTBvCyLWLlWnbaUkZdEYbKHBPjd8t/1x5Yg==\r\n'),
	('S',b'+ YGgGCSqGSIb3EgECAgIAb1kwV6ADAgEFoQMCAQ+iSzBJoAMCAQGiQgRAtHTEuOP2BXb9sBYFR4SJlDZxmg39IxmRBOhXRKdDA0uHTCOT9Bq3OsUTXUlk0CsFLoa8j+gvGDlgHuqzWHPSQg==\r\n'),
	('C',b'\r\n'),
	('S',b'+ YDMGCSqGSIb3EgECAgIBAAD/////6jcyG4GE3KkTzBeBiVHeceP2CWY0SR0fAQAgAAQEBAQ=\r\n'),
	('C',b'YDMGCSqGSIb3EgECAgIBAAD/////3LQBHXTpFfZgrejpLlLImPwkhbfa2QteAQAgAG1yYwE=\r\n'),
	('S',b'A001 OK GSSAPI authentication successful\r\n'),
]

comms5 = [
	('C',b'a001 LOGIN SMITH SESAME\r\n'),
	('S',b'a001 OK LOGIN completed\r\n'),
]

comms6 = [
	('C',b'A142 SELECT INBOX\r\n'),
	('S',b'* 172 EXISTS\r\n'),
	('S',b'* 1 RECENT\r\n'),
	('S',b'* OK [UNSEEN 12] Message 12 is first unseen\r\n'),
	('S',b'* OK [UIDVALIDITY 3857529045] UIDs valid\r\n'),
	('S',b'* OK [UIDNEXT 4392] Predicted next UID\r\n'),
	('S',b'* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)\r\n'),
	('S',b'* OK [PERMANENTFLAGS (\Deleted \Seen \*)] Limited\r\n'),
	('S',b'A142 OK [READ-WRITE] SELECT completed\r\n'),
]

comms7 = [
	('C',b'A932 EXAMINE blurdybloop\r\n'),
	('S',b'* 17 EXISTS\r\n'),
	('S',b'* 2 RECENT\r\n'),
	('S',b'* OK [UNSEEN 8] Message 8 is first unseen\r\n'),
	('S',b'* OK [UIDVALIDITY 3857529045] UIDs valid\r\n'),
	('S',b'* OK [UIDNEXT 4392] Predicted next UID\r\n'),
	('S',b'* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)\r\n'),
	('S',b'* OK [PERMANENTFLAGS ()] No permanent flags permitted\r\n'),
	('S',b'A932 OK [READ-ONLY] EXAMINE completed\r\n'),
]

comms8 = [
	('C',b'A003 CREATE owatagusiam/\r\n'),
	('S',b'A003 OK CREATE completed\r\n'),
	('C',b'A004 CREATE owatagusiam/blurdybloop\r\n'),
	('S',b'A004 OK CREATE completed\r\n'),
]

comms9 = [
	('C',b'A682 LIST "" *\r\n'),
	('S',b'* LIST () "/" blurdybloop\r\n'),
	('S',b'* LIST (\Noselect) "/" foo\r\n'),
	('S',b'* LIST () "/" foo/bar\r\n'),
	('S',b'A682 OK LIST completed\r\n'),
	('C',b'A683 DELETE blurdybloop\r\n'),
	('S',b'A683 OK DELETE completed\r\n'),
	('C',b'A684 DELETE foo\r\n'),
	('S',b'A684 NO Name "foo" has inferior hierarchical names\r\n'),
	('C',b'A685 DELETE foo/bar\r\n'),
	('S',b'A685 OK DELETE Completed\r\n'),
	('C',b'A686 LIST "" *\r\n'),
	('S',b'* LIST (\Noselect) "/" foo\r\n'),
	('S',b'A686 OK LIST completed\r\n'),
	('C',b'A687 DELETE foo\r\n'),
	('S',b'A687 OK DELETE Completed\r\n'),
	('C',b'A82 LIST "" *\r\n'),
	('S',b'* LIST () "." blurdybloop\r\n'),
	('S',b'* LIST () "." foo\r\n'),
	('S',b'* LIST () "." foo.bar\r\n'),
	('S',b'A82 OK LIST completed\r\n'),
	('C',b'A83 DELETE blurdybloop\r\n'),
	('S',b'A83 OK DELETE completed\r\n'),
	('C',b'A84 DELETE foo\r\n'),
	('S',b'A84 OK DELETE Completed\r\n'),
	('C',b'A85 LIST "" *\r\n'),
	('S',b'* LIST () "." foo.bar\r\n'),
	('S',b'A85 OK LIST completed\r\n'),
	('C',b'A86 LIST "" %\r\n'),
	('S',b'* LIST (\Noselect) "." foo\r\n'),
	('S',b'A86 OK LIST completed\r\n'),
]

comms10 = [
	('C',b'A682 LIST "" *\r\n'),
	('S',b'* LIST () "/" blurdybloop\r\n'),
	('S',b'* LIST (\Noselect) "/" foo\r\n'),
	('S',b'* LIST () "/" foo/bar\r\n'),
	('S',b'A682 OK LIST completed\r\n'),
	('C',b'A683 RENAME blurdybloop sarasoop\r\n'),
	('S',b'A683 OK RENAME completed\r\n'),
	('C',b'A684 RENAME foo zowie\r\n'),
	('S',b'A684 OK RENAME Completed\r\n'),
	('C',b'A685 LIST "" *\r\n'),
	('S',b'* LIST () "/" sarasoop\r\n'),
	('S',b'* LIST (\Noselect) "/" zowie\r\n'),
	('S',b'* LIST () "/" zowie/bar\r\n'),
	('S',b'A685 OK LIST completed\r\n'),
	('C',b'Z432 LIST "" *\r\n'),
	('S',b'* LIST () "." INBOX\r\n'),
	('S',b'* LIST () "." INBOX.bar\r\n'),
	('S',b'Z432 OK LIST completed\r\n'),
	('C',b'Z433 RENAME INBOX old-mail\r\n'),
	('S',b'Z433 OK RENAME completed\r\n'),
	('C',b'Z434 LIST "" *\r\n'),
	('S',b'* LIST () "." INBOX\r\n'),
	('S',b'* LIST () "." INBOX.bar\r\n'),
	('S',b'* LIST () "." old-mail\r\n'),
	('S',b'Z434 OK LIST completed\r\n'),
	('C',b'A002 SUBSCRIBE #news.comp.mail.mime\r\n'),
	('S',b'A002 OK SUBSCRIBE completed\r\n'),
	('C',b'A002 UNSUBSCRIBE #news.comp.mail.mime\r\n'),
	('S',b'A002 OK UNSUBSCRIBE completed\r\n'),
]

#parse_comm(comms1)
#parse_comm(comms2)
#parse_comm(comms3)
#parse_comm(comms4)
#parse_comm(comms5)
#parse_comm(comms6)
#parse_comm(comms7)
#parse_comm(comms8)
#parse_comm(comms9)
parse_comm(comms10)
