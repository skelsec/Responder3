#!/usr/bin/env python3.6

from ftplib import FTP

username = 'alma'
password = 'alma'

ftp = FTP('127.0.0.1')
ftp.login(username, password)
ftp.close()
