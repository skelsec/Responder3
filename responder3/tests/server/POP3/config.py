startup = {
	'mode' : 'TEST',
	}

logsettings = {
	'log' : {
		'version': 1,
		'formatters': {
			'detailed': {
				'class': 'logging.Formatter',
					'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
			}
		},
		'handlers': {
			'console': {
				'class': 'logging.StreamHandler',
				'level': 'DEBUG',
			}
		},
		'root': {
			'level': 'DEBUG',
			'handlers': ['console']
		}
	}
}

sslctx = {
			'certfile':'../testcert/responder3.crt',
			'keyfile' :'../testcert/responder3.key',
			'protocols' :'PROTOCOL_SSLv23',
			'options' :'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode' :'CERT_NONE',
			'ciphers' :'ALL',
		}

sslctx_nofile = {
			'certdata': '-----BEGIN CERTIFICATE-----\r\n'
						'MIICszCCAhygAwIBAgIIWtNRgLvmptkwDQYJKoZIhvcNAQELBQAwejELMAkGA1UE\r\n'
						'BhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxEDAOBgNVBAcMB05ld2J1cnkx\r\n'
						'HjAcBgNVBAoMFUNvZGV4IE5vbiBTdWZmaWNpdCBMQzEhMB8GA1UEAwwYcmVzcG9u\r\n'
						'ZGVyMl90ZXN0X2NlcnRfc3RyMB4XDTE4MDQxNTEzMjAwMFoXDTE5MDQxNTEzMjAw\r\n'
						'MFowejELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxEDAOBgNV\r\n'
						'BAcMB05ld2J1cnkxHjAcBgNVBAoMFUNvZGV4IE5vbiBTdWZmaWNpdCBMQzEhMB8G\r\n'
						'A1UEAwwYcmVzcG9uZGVyMl90ZXN0X2NlcnRfc3RyMIGfMA0GCSqGSIb3DQEBAQUA\r\n'
						'A4GNADCBiQKBgQCzEMd/Rb7ItIVXY3nrgJ3zCONI2xiUad6clv/8UR/D1SSX8oLW\r\n'
						'94buSxLBWXWqtku3dkjsfiAsb7p1qiqXNU3XOohtxt6oCqbq62+DjRO03ah6X/BK\r\n'
						'rTU9EJnowr6SneSDjxd97MbbPBdhdpPHrXW3r+zuznhl1gfW9+jd0IvCbwIDAQAB\r\n'
						'o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT9W1XliyzwSPDzb+C7j18d\r\n'
						'r/fEFzAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADgYEAD2ddz4RuZW/+\r\n'
						'yzYVlvMtVssLyY8LitfGPOiEJ0WWJDokoe1SGp0nqm1vFxS8AxwJYZwJ2DNedCNr\r\n'
						'rCffMag46qXq4VkqNLew7fOA02RymFinx1HlEDlxBCz9l3wZflJwGU+Oj5Qr4EOn\r\n'
						'6fVn/TpnKU+FAjaGZeNBbQJObH4iTuU=\r\n'
						'-----END CERTIFICATE-----\r\n',
			'keydata':	'-----BEGIN PRIVATE KEY-----\r\n'
						'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALMQx39Fvsi0hVdj\r\n'
						'eeuAnfMI40jbGJRp3pyW//xRH8PVJJfygtb3hu5LEsFZdaq2S7d2SOx+ICxvunWq\r\n'
						'Kpc1Tdc6iG3G3qgKpurrb4ONE7TdqHpf8EqtNT0QmejCvpKd5IOPF33sxts8F2F2\r\n'
						'k8etdbev7O7OeGXWB9b36N3Qi8JvAgMBAAECgYBBHaDuT1aJddvnY206jpLhhiHg\r\n'
						'pIvTrIwfNWnxPy7l7+RWvQGHWoveq74uQXHgmln+ZS0vks3wWtDbaP4D7oZXWmHH\r\n'
						'emCzCr+7O/GsNKxDVR7oyyZtzazkxZn4XOt1KfIN+fefmY+OU9czt5pX7hntOPv0\r\n'
						'03C5Ko3X7V1HOAb7wQJBANb134TRDsI6+He/cooza3XY7NWpRJIWc8nhsPjXueA6\r\n'
						'2gqAVPaEjU/0+csIPxmQz0l0HL2f41clAtSLOTIvgPUCQQDVQI3IoA88BGrOo9yx\r\n'
						'1aF5UUBDN7eacl/krnF2gP3Og64HfrzX2N0NrO/NxJlqih/4CHD3Q3L9/o8ZFWiU\r\n'
						'PUdTAkEAo9T/R34Cbpx9VN8QEC7Cfy4Wy31X6rO8Cii+NdpNK44PMqO+nahG/6Kp\r\n'
						'Y0nktbp9kfEyGoAqx/dIYe++ZvZ3pQJBAIAOBZXl14AYvvJbH5mCSTaKfeZfPNd3\r\n'
						'uvGddvDMQJyUIhrKFigfR46AvHd5iQ6a5tuQZhV04UZ4aAGOA4CQ05UCQFuaqmN/\r\n'
						'FHLI5uMBGd1qlU6xPfYz490qRIAHwUwU84lpgi3WV0gt/cpAuzS+9/P2N5KY9rNA\r\n'
						'0lT8gwNBDcHVV6w=\r\n'
						'-----END PRIVATE KEY-----\r\n',
			'protocols':'PROTOCOL_SSLv23',
			'options':'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode':'CERT_NONE',
			'ciphers':'ALL',
		}




servers = [
	{
		'handler'  : 'POP3',
	},
	{
		'handler'  : 'POP3',
		'bind_port':[(995, 'tcp')],
		'bind_sslctx' : sslctx,
	},
]