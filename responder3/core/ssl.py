import os
import ssl
import tempfile
from pathlib import Path


class SSLContextBuilder:
	doc_sslsettings = {
		'protocols':'',
		'options':'',
		'verify_mode':'',
		'ciphers':'',
		'server_side':'',
		'certfile':'',
		'keyfile':'',
		'certdata':'',
		'keydata':'',
	}
	"""
	Holds the necessary config elements to setup an ssl context.
	certfile and certdata are mutually exclusive. Only provide one.
	:param protocols: List of ssl.protocol values as string
	:type protocols: list
	:param options: List of ssl.options values as string
	:type protocols: list
	:param verify_mode: The verification mode as string
	:type verify_mode: str
	:param ciphers: Cipher settings string
	:type ciphers: str
	:param server_side: Determines whether we use this context as a client or as a server
	:type server_side: bool
	:param certfile: Full path to the certificate file
	:type certfile: str
	:param keyfile: Full path to the key file
	:type keyfile: str
	:param certdata: PEM formatted string holding the certificate
	:type certdata: key
	:param keydata: PEM formatted string holding the key data
	:type keydata: str
	"""

	def __init__(self):
		"""
		Parses the user-supplied setting and create an ssl.SSLContext class
		"""
		pass

	@staticmethod
	def from_dict(sslsettings, server_side=False):
		"""
		Creates SSL context from dictionary-based configuration
		:param sslsettings: configuration dictionary
		:param server_side: decides that the context will be created as a server or client
		:return: ssl.SSLContext

		:TODO: if python devs come up with a way to load certificates/key from string rather than from a file then rewrite the certdata part
		"""
		protocol = ssl.PROTOCOL_SSLv23
		options = []
		verify_mode = ssl.CERT_NONE
		ciphers = 'ALL'
		check_hostname = None

		if 'protocol' in sslsettings:
			"""
			protocols = []
			if isinstance(sslsettings['protocols'], list):
				for proto in sslsettings['protocols']:
					protocols.append(getattr(ssl, proto, 0))
			else:
				protocols.append(getattr(ssl, sslsettings['protocols'], 0))
			"""
			protocol = getattr(ssl, sslsettings['protocol'])

		if 'options' in sslsettings:
			options = []
			if isinstance(sslsettings['options'], list):
				for option in sslsettings['options']:
					options.append(getattr(ssl, proto, 0))
			else:
				options.append(getattr(ssl, sslsettings['options'], 0))

		if 'verify_mode' in sslsettings:
			verify_mode = getattr(ssl, sslsettings['verify_mode'], 0)

		if 'ciphers' in sslsettings:
			ciphers = sslsettings['ciphers']

		if server_side is None:
			if 'server_side' in sslsettings:
				server_side = sslsettings['server_side']
				
		if server_side == False:
			check_hostname = True #hey! security first! (or something)
			if 'check_hostname' in sslsettings:
				check_hostname = sslsettings['check_hostname']
			
			

		context = ssl.SSLContext(protocol)
		context.verify_mode = verify_mode
		
		if check_hostname:
			context.check_hostname = check_hostname

		# server_side>you need certs, if you are a client, you might need certs
		if server_side or 'certfile' in sslsettings or 'certdata' in sslsettings:
			if 'certfile' in sslsettings:
				context.load_cert_chain(
					certfile=sslsettings['certfile'],
					keyfile=sslsettings['keyfile']
				)
			if 'certdata' in sslsettings:
				# not using tempfile.NamedTemporaryFile here because it cannot be re-opened in windows as per documentation
				with tempfile.TemporaryDirectory() as td:
					random_suffix = os.urandom(8).hex()
					certfile = '%s%s%s' % ('cert', random_suffix, '.crt')
					certfile_path = str(Path(td, certfile))
					print(certfile_path)
					keyfile = '%s%s%s' % ('key', random_suffix, '.crt')
					keyfile_path = str(Path(td, keyfile))
					print(keyfile_path)
					with open(certfile_path, 'w') as f:
						f.write(sslsettings['certdata'])
						f.flush()
						os.fsync(f.fileno())

					with open(keyfile_path, 'w') as f:
						f.write(sslsettings['keydata'])
						f.flush()
						os.fsync(f.fileno())

					context.load_cert_chain(
						certfile=certfile_path,
						keyfile=keyfile_path
					)
		if verify_mode != ssl.CERT_NONE:
			if 'cafile' in sslsettings:
				context.load_verify_locations(sslsettings['cafile'])
			elif 'cadata' in sslsettings:
				with tempfile.TemporaryDirectory() as td:
					random_suffix = os.urandom(8).hex()
					cafile = '%s%s%s' % ('cert', random_suffix, '.crt')
					cafile_path = str(Path(td, cafile))
					print(certfile_path)
					
					with open(certfile_path, 'w') as f:
						f.write(sslsettings['cadata'])
						f.flush()
						os.fsync(f.fileno())
						
					context.load_verify_locations(
						certfile_path
					)
			
			else:
				raise Exception('Verify mode of %s needs "cafile " or "cadata" to be set in the settings!' % verify_mode)
		
		else:
			if 'cafile' in sslsettings:
				context.load_verify_locations(sslsettings['cafile'])
		
			if 'cadata' in sslsettings:
				with tempfile.TemporaryDirectory() as td:
					random_suffix = os.urandom(8).hex()
					cafile = '%s%s%s' % ('cert', random_suffix, '.crt')
					cafile_path = str(Path(td, cafile))
					print(certfile_path)
					
					with open(certfile_path, 'w') as f:
						f.write(sslsettings['cadata'])
						f.flush()
						os.fsync(f.fileno())
						
					context.load_verify_locations(
						certfile_path
					)

		#context.protocol = 0
		context.options = 0
		#for p in protocols:
		#	context.protocol |= p
		for o in options:
			context.options |= o
		context.set_ciphers(ciphers)
		return context
