#!/usr/bin/env python3.6
import sys
import time
import imaplib
from responder3.core.test_helper import setup_test, read_to_creds

username = 'alma'
password = 'alma'

r3, global_config, output_queue = setup_test(__file__)
r3_process = r3.start()

time.sleep(1)


#Test1
try:
	M = imaplib.IMAP4('localhost', 143)
	M.login(username, password)
	M.close()
except:
	pass
# M.select()
# typ, data = M.search(None, 'ALL')
# M.logout()
#M.close()
cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #1 PASS')

#Test2
M = imaplib.IMAP4_SSL('localhost', 993)
M.login(username, password)
# M.select()
# typ, data = M.search(None, 'ALL')
# M.close()
#M.logout()
cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #2 PASS')
sys.exit()
