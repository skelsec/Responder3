#!/usr/bin/env python3.6
import sys
import time
from ftplib import FTP
from responder3.core.test_helper import setup_test, read_to_creds

username = 'alma'
password = 'alma'

r3, global_config, output_queue = setup_test(__file__)
r3_process = r3.start()

time.sleep(1)

ftp = FTP('127.0.0.1')
ftp.login(username, password)
ftp.close()

cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #1 PASS')
sys.exit()