from oscrypto import asymmetric
from certbuilder import CertificateBuilder, pem_armor_certificate
import sys
import pathlib

def generate_cert_and_key(cn, filename, keysize, keytype = 'rsa'):
	ca_key_name  = '%s.key' % filename
	ca_cert_name = '%s.crt' % filename

	curdir = pathlib.Path(__file__).parent


	# Generate and save the key and certificate for the root CA
	root_ca_public_key, root_ca_private_key = asymmetric.generate_pair(keytype, bit_size=keysize)

	with open(curdir.joinpath(ca_key_name), 'wb') as f:
		f.write(asymmetric.dump_private_key(root_ca_private_key, None))

	builder = CertificateBuilder(
		{
			'country_name': 'US',
			'state_or_province_name': 'Massachusetts',
			'locality_name': 'Newbury',
			'organization_name': 'Codex Non Sufficit LC',
			'common_name': cn,
		},
		root_ca_public_key
	)
	builder.self_signed = True
	builder.ca = True
	root_ca_certificate = builder.build(root_ca_private_key)

	with open(curdir.joinpath(ca_cert_name), 'wb') as f:
		f.write(pem_armor_certificate(root_ca_certificate))


if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Quick self-signed cert generator')
	parser.add_argument('cn', default=1024, help='CN field')
	parser.add_argument('-o', default='responder3', help='output file base name')
	parser.add_argument('-b', type=int, default=1024, help='RSA key size in bits')
	args =  parser.parse_args()
	
	print('[+] Genearting cert and key...')
	generate_cert_and_key(args.cn, args.o, args.b)
	print('[+] Done!')