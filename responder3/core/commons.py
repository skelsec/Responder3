#!/usr/bin/env python
import os
import queue
import base64
import enum
import datetime
import socket
import errno
import threading
from multiprocessing import Manager
from multiprocessing.managers import BaseManager, SyncManager



import os
import sys
import re
import logging
import socket
import time
import datetime
import json
import enum

from responder3.crypto.hashing import *

#class ResponderManager(BaseManager): pass


class LogEntry():
	"""
	Communications object that is used to pass log information to the LogProcessor
	"""
	def __init__(self, level, name, msg):
		"""
		level: the log level, needs to be a level specified by the built-in logging module (eg. logging.INFO)
		name : name of the source module
		msg  : message that is to be printed in the logs 
		"""
		self.level = level
		self.name  = name
		self.msg   = msg

	def __str__(self):
		return "[%s] %s" % (self.name, self.msg)


class ConnectionStatus(enum.Enum):
	OPENED = 0
	CLOSED = 1
	STATELESS = 3

class ConnectionFactory():
	"""
	Creates Connetion object from the socket input. 
	in: rdns which is a shared dictionary to speed up the rdns lookup
	"""
	def __init__(self, rdnsd):
		self.rdnsd       = rdnsd

	def from_streamwriter(self, writer, protocoltype):
		con = Connection()
		con.timestamp = datetime.datetime.utcnow()
		if protocoltype == ServerProtocol.TCP:
			soc = writer.get_extra_info('socket')
			con.local_ip, con.local_port   = soc.getsockname()
			con.remote_ip, con.remote_port = soc.getpeername()
		
		else:
			con.local_ip, con.local_port   = writer._laddr[:2]
			con.remote_ip, con.remote_port = writer._addr[:2]
		
		self.lookupRDNS(con)
		return con
		
	def lookupRDNS(self, con):
		"""
		Reolves the remote host's IP address to a DNS address. 
		First checks if the address has already been resolved by looking it up in the shared rdns dictionary
		"""
		#if con.remote_ip in self.rdnsd :
		if con.remote_ip in self.rdnsd:
			con.remote_dns = self.rdnsd[con.remote_ip]
		
		else:
			try:
				con.remote_dns = socket.gethostbyaddr(con.remote_ip)[0]
			except Exception as e:
				pass

			self.rdnsd[con.remote_ip] = con.remote_dns


class Connection():
	"""
	Keeps all the connection related information that is used for logging and/or connection purposes
	"""
	def __init__(self):
		self.remote_ip   = None
		self.remote_dns  = None
		self.remote_port = None
		self.local_ip    = None
		self.local_port  = None
		self.timestamp   = None


	def getRemoteAddress(self):
		return (self.remote_ip, self.remote_port)

	def toDict(self):
		t = {}
		t['remote_ip']   = self.remote_ip
		t['remote_port'] = self.remote_port
		t['remote_dns']  = self.remote_dns
		t['local_ip']    = self.local_ip
		t['local_port']  = self.local_port
		t['timestamp']   = self.timestamp
		return t

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.remote_dns is not None:
			return '[%s] %s:%d -> %s:%d' % (self.timestamp.isoformat(), self.remote_dns, self.remote_port, self.local_ip,self.local_port )
		else:
			return '[%s] %s:%d -> %s:%d' % (self.timestamp.isoformat(), self.remote_ip, self.remote_port, self.local_ip,self.local_port )


class Credential():
	def __init__(self, credtype, domain = None, username = None, password = None, data = None):
		self.type     = credtype
		self.domain   = domain
		self.username = username
		self.password = password
		self.data     = data
		self.module   = None
		self.client_addr  = None
		self.client_rdns  = None

class PoisonResult():
	def __init__(self):
		self.module = None
		self.target = None
		self.request_name = None
		self.request_type = None
		self.poison_name = None
		self.poison_addr = None
		self.mode = None

	def __repr__(self):
		return str(self)
		

	def __str__(self):
		if self.mode == PoisonerMode.ANALYSE:
			return '[%s] Recieved request from IP: %s to resolve: %s' % (self.module, self.target, self.request_name)
		else:
			return '[%s] Spoofing target: %s for the request: %s which matched the expression %s. Spoof address %s' % (self.module, self.target, self.request_name, self.poison_name, self.poison_addr)

class EmailEntry():
	"""
	If the SMTP server recieved an email it's sent to the log queue for processing
	"""
	def __init__(self):
		self.fromAddress = None #string
		self.toAddress   = None #list
		self.email       = None #email object (from the email package)

class UniversalEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		elif isinstance(obj, enum.Enum):
			return obj.value
		else:
			return json.JSONEncoder.default(self, obj)

def timestamp2datetime(dt):
	us = int.from_bytes(dt, byteorder='little')/ 10.
	return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=us)

class PoisonerMode(enum.Enum):
	SPOOF = enum.auto()
	ANALYSE = enum.auto()

class ServerFunctionality(enum.Enum):
	HONEYPOT = 0
	SERVER   = 1
	TARPIT   = 2
	
class ServerProtocol(enum.Enum):
	TCP = 0
	UDP = 1
	SSL = 2

#values MUST be lists!
defaultports = {
	"DNS"  : [(53, 'udp'),(53, 'tcp')],
	"DHCP" : [(67, 'udp')],
	"NTP"  : [(123, 'udp')],
 	"HTTP" : [(80, 'tcp')],
	"HTTPS": [(443, 'tcp')],
	"FTP"  : [(21, 'tcp')],
	"SMTP" : [(25, 'tcp')],
	"POP3" : [(110, 'tcp')],
	"POP3S": [(995, 'tcp')],
	"IMAP" : [(143, 'tcp')],
	"IMAPS": [(993, 'tcp')],
	"SMB"  : [(445, 'tcp')],
	"NBTNS": [(137, 'udp')],
	"SOCKS5":[(1050, 'tcp')],
	"LLMNR": [(5355, 'udp')],
	"MDNS" : [(5353, 'udp')],
	"HTTPProxy":[(8080, 'tcp')],
}