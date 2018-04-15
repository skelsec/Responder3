#!/usr/bin/env python3.6
import time
from ftplib import FTP
from responder3.core.test_helper import setup_test

username = 'alma'
password = 'alma'

r3, global_config = setup_test(__file__)
r3_process = r3.start_process()

time.sleep(1)

ftp = FTP('127.0.0.1')
ftp.login(username, password)
ftp.close()
