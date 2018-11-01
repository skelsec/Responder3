
#https://cryptography.io/en/latest/x509/tutorial/
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

def genRSAPrivKey(keysize = 2048, pubexp = 65537):
	return rsa.generate_private_key(
		public_exponent=pubexp,
		key_size=keysize,
		backend=default_backend()
		)

def genSSC(key, subject, issuer, san = u'localhost', validity_days = 3650):
	return x509.CertificateBuilder(
	).subject_name(subject
	).issuer_name(issuer
	).public_key(key.public_key()
	).serial_number(x509.random_serial_number()
	).not_valid_before(datetime.datetime.utcnow()
	).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
	).add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),critical=False,
	).sign(key, hashes.SHA256(), default_backend())

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Generate self signed certificate')
	parser.add_argument('CN', default=u'localhost', help='Common name')
	parser.add_argument('--keysize', type=int, default=2048, help='RSA private key size')
	parser.add_argument('--keyfile', default='responder.key', help='output key file location')
	parser.add_argument('--certfile', default='responder.pem', help='output cert file location')


	args = parser.parse_args()

	key = genRSAPrivKey(keysize = args.keysize)
	
	with open(args.keyfile, "wb") as f:
		f.write(key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		))

	subject = issuer = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
		x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
		x509.NameAttribute(NameOID.COMMON_NAME, args.CN),
	])

	cert = genSSC(key,subject, subject, san = args.CN)
	# Write our CSR out to disk.
	with open(args.certfile, "wb") as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))
