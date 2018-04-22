#!/usr/bin/env python3.6
import time
import poplib
import sys
from responder3.core.test_helper import setup_test, read_to_creds

username = 'alma'
password = 'alma'

r3, global_config, output_queue = setup_test(__file__)
r3_process = r3.start()

time.sleep(1)

Mailbox = poplib.POP3('localhost', '110')
Mailbox.user(username)
Mailbox.pass_(password)

cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #1 PASS')

Mailbox = poplib.POP3_SSL('localhost', '995')
Mailbox.user(username)
Mailbox.pass_(password)

cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #2 PASS')


Mailbox = poplib.POP3('localhost', '110')
Mailbox.apop(username, password)

cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #3 PASS')
sys.exit()
