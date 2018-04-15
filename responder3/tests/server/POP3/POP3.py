#!/usr/bin/env python3.6
import time
import poplib
from responder3.core.test_helper import setup_test

username = 'alma'
password = 'alma'

r3, global_config = setup_test(__file__)
r3_process = r3.start_process()

time.sleep(1)

Mailbox = poplib.POP3('localhost', '110')
Mailbox.user(username)
Mailbox.pass_(password)

Mailbox = poplib.POP3_SSL('localhost', '995')
Mailbox.user(username)
Mailbox.pass_(password)


Mailbox = poplib.POP3('localhost', '110')
Mailbox.apop(username, password)
