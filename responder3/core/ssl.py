import os
import ssl
from ssl import VerifyMode
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
	def load_certificates(context, sslsettings):
		#or 'certfile' in sslsettings or 'certdata' in sslsettings:
		if 'certfile' in sslsettings:
			print('loading certfile!')
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
				#print(certfile_path)
				keyfile = '%s%s%s' % ('key', random_suffix, '.crt')
				keyfile_path = str(Path(td, keyfile))
				#print(keyfile_path)
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

	@staticmethod
	def load_ca_certs(context, sslsettings):
		if 'cafile' in sslsettings:
			context.load_verify_locations(sslsettings['cafile'])
		elif 'cadata' in sslsettings:
			with tempfile.TemporaryDirectory() as td:
				random_suffix = os.urandom(8).hex()
				cafile = '%s%s%s' % ('cert', random_suffix, '.crt')
				cafile_path = str(Path(td, cafile))
				#print(certfile_path)
						
				with open(certfile_path, 'w') as f:
					f.write(sslsettings['cadata'])
					f.flush()
					os.fsync(f.fileno())
							
				context.load_verify_locations(
					certfile_path
				)
				
		else:
			raise Exception('Verify mode of %s needs "cafile " or "cadata" to be set in the settings!' % verify_mode)

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
		if server_side == True:
			SSLContextBuilder.load_certificates(context, sslsettings)
		
		else:
			if verify_mode != VerifyMode.CERT_NONE:
				SSLContextBuilder.load_certificates(context, sslsettings)
				SSLContextBuilder.load_ca_certs(context, sslsettings)
			else:
				SSLContextBuilder.load_ca_certs(context, sslsettings)

		#context.protocol = 0
		context.options = 0
		#for p in protocols:
		#	context.protocol |= p
		for o in options:
			context.options |= o
		context.set_ciphers(ciphers)
		return context

def get_default_server_ctx():
	d = {
			'protocols'  : 'PROTOCOL_SSLv23',
			'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode': 'CERT_NONE',
			'ciphers'    : 'ALL',
			'server_side': True,
			'certdata'   : '-----BEGIN CERTIFICATE-----\r\n'\
							'MIIDEzCCAfugAwIBAgIBAjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhyM3Rl\r\n'\
							'c3RDQTAeFw0xODExMDEyMDM3MDBaFw0yODExMDEyMDM3MDBaMBYxFDASBgNVBAMM\r\n'\
							'C3Rlc3Rfc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtd1A\r\n'\
							'TN7yDtJH5h1PHDOjBSZzd4PO1/EL35UyeRJ7uwUk6NyCgiwUicr+sMEVqKkiAaNN\r\n'\
							'xbhGiJv9+uWtJWkSyhpBb2kDlXq/aBA1aAJ1U7y1CAK6QOTrxO9+ugLJuILsY5i/\r\n'\
							'N4GERITeJgCwRdDaOCR3EzeG8mt+znQNwE3vdD3DCpNGSDMenyCF/STjBcpdXABF\r\n'\
							'1CNeSnzEZUZ5enp2yg2oCTCbgN8yuTftM04gWyhojeYXitRJRYAE7INNqYGPyg73\r\n'\
							'mXY4rN6mIgeVIhaWSYxpjp6g7LXOr0xNsBnt2pctf9zpYbq40HxI4SNBqB/9lwXV\r\n'\
							'7PPC2cuWg2QEuCZANQIDAQABo28wbTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTv\r\n'\
							'Wx/+SvpZgV8dyYVoGZ3norTwWzALBgNVHQ8EBAMCBeAwEQYJYIZIAYb4QgEBBAQD\r\n'\
							'AgZAMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQEL\r\n'\
							'BQADggEBAGB56E1cfRmoum67ska+3qo4xM41uU40rm+VnGQpcBhloNEZ8fGL/vB6\r\n'\
							'0eJXsGe2uju49QfXccIV7JEawOauifc7cYYMNGKDCcPAXa3FXsCzRkkw+hO8l5zK\r\n'\
							'qgtbcqy+ov0I2bn09iM3CdB9ZhyISPBcPTtGFQjRJSX2NXQbfOTlz5CWyqb8bR/g\r\n'\
							'QqF1upvc0xzjJRjg/5VSxBdsBwqbH80vyiFBP9C919IfpUm+HDLe4Gps5NV5w+VT\r\n'\
							'GVC3WHkWU5PUUbwaD0b1O32rYiihYrPLYWFLqDPzhWPTZjpBr/Ehu/WbGVtSQmFv\r\n'\
							'g1T4Y9c1mGDYzyOy2/zeQWpWGZ0VnaE=\r\n'\
							'-----END CERTIFICATE-----\r\n',
			'keydata'    :  '-----BEGIN RSA PRIVATE KEY-----\r\n'\
							'MIIEowIBAAKCAQEAtd1ATN7yDtJH5h1PHDOjBSZzd4PO1/EL35UyeRJ7uwUk6NyC\r\n'\
							'giwUicr+sMEVqKkiAaNNxbhGiJv9+uWtJWkSyhpBb2kDlXq/aBA1aAJ1U7y1CAK6\r\n'\
							'QOTrxO9+ugLJuILsY5i/N4GERITeJgCwRdDaOCR3EzeG8mt+znQNwE3vdD3DCpNG\r\n'\
							'SDMenyCF/STjBcpdXABF1CNeSnzEZUZ5enp2yg2oCTCbgN8yuTftM04gWyhojeYX\r\n'\
							'itRJRYAE7INNqYGPyg73mXY4rN6mIgeVIhaWSYxpjp6g7LXOr0xNsBnt2pctf9zp\r\n'\
							'Ybq40HxI4SNBqB/9lwXV7PPC2cuWg2QEuCZANQIDAQABAoIBAGLA4MCdM22u69Hd\r\n'\
							'ym5y76vFRF/6l+AUiTEAcCbkTYGxemhkDQ4oZ4KnUwOh5WPva4LeLUYXGV3m7tRF\r\n'\
							'0W6GDujltvCLYqHRxIv6eTWgWBt/VgIikQbaB9ipf/P7vZPOrBQtBnBaiPs39vVF\r\n'\
							'3HIcxdJEotAxj7qlenca97ib2VIRqGKI4xr36UdYs3XW2Ip1zatZPLTMBVroyLpY\r\n'\
							'f9ytiXz7QlQH5mBE99oIksKrAz/z38zXZ18yIZJQRwnbC/nOapEeokMpRu61opEl\r\n'\
							'e50K/qIKhrdGJJ+20BLIAa05W8jRC8ezZ7Hb+5XI4bl5HJF8IpVMqi1ZVLssQo3F\r\n'\
							'S1N9egECgYEA6syeCP/b5hbV6z28SH4lT7fXAaakxxUt0otzt0lV2wUvsfvF3S9p\r\n'\
							'WV4OYKvJrSapbzsGLseSjQE8ho9OIxpscPX4iqALhnbnY21DeSMY/zigLHPHX0mP\r\n'\
							'SDInlfI+W+LapnHNU6ofZA5K+tN5WWAzskXmC5G3TPsGIv6A1YOANLUCgYEAxkkK\r\n'\
							'mZIgMA5yGyv8t8jAe1B6cF40X2+77lM220ZgMTLfvFmjnQgypwPXxez4jHoAAgth\r\n'\
							'/1ivxV7fvny6xl/J6IM8orKmKk8GQAganyzq50KxxxoSd8yasmqGlXoHVDsMbEoK\r\n'\
							'RBFI9BtEn5OJ2impWYdE12mpt4IumkVgOw/0jYECgYEAqSr3ieBeHO7C/ZQjPc+1\r\n'\
							'LjR0MnpQKie2NgXHP30U4JJiBMgzjOMF8h90GG5tBdXfKYbLM5USn4kOhJxnXZ9C\r\n'\
							'FjkB807QPvcYS2iDvpls/yVbMevQ73ReSVPpdX1tNGLDyjwgBXGC4GHz37fRrHVF\r\n'\
							'ieIWlqtL96i8iSX4yNzP2CkCgYBca+Ev8YdlPuZ6uccCluT41WssgwxgS4FKNalF\r\n'\
							'DYl6hR75+MIlSJPrewQQ8kJrn9XvHgUgcuMC2RTrAdJA8pb29GzH3QNMhyb/o4dd\r\n'\
							'GB+piVG53vIqusiETtjKRWWzIg7JTr14OqJJfYg/5RIFCRQxcbZpvYtoyJoWOC4B\r\n'\
							'eY9ggQKBgDEMW8ZkNFgXpj+j7zxGpp/TQUtM4LL/uGa4Du3Wicz7T/Ho6lmVkLCZ\r\n'\
							'GWQrsJZjqI512qFKDTVWX7nOap+oGqGBF4VnefvO9RVoB6wVqb3FpZRx8elUyPXN\r\n'\
							'oChY/SCgtGktqGgtcHYiFXVUqHW8cHTk9Sb0YL4T8xLMrab2j13C\r\n'\
							'-----END RSA PRIVATE KEY-----\r\n',
			
		}
	return SSLContextBuilder.from_dict(d)