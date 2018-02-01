from responder3.crypto.symmetric import getSpecificCipher
from responder3.crypto.BASE import cipherMODE

"""
the folwing tests are NOT cryptographic tests, rather it supposed to test that all cipher versions with all libraries start and can perform crypto operations

"""
rc4_test_vectors = [
	(bytes.fromhex('0102030405'),bytes.fromhex('b2396305f03dc027ccc3524a0a1118a86982944f18fc82d589c403a47a0d0919')),
	(bytes.fromhex('01020304050607'),bytes.fromhex('293f02d47f37c9b633f2af5285feb46be620f1390d19bd84e2e0fd752031afc1')),
	(bytes.fromhex('0102030405060708'),bytes.fromhex('97ab8a1bf0afb96132f2f67258da15a88263efdb45c4a18684ef87e6b19e5b09')),
	(bytes.fromhex('0102030405060708090a'),bytes.fromhex('ede3b04643e586cc907dc2185170990203516ba78f413beb223aa5d4d2df6711')),
	(bytes.fromhex('0102030405060708090a0b0c0d0e0f10'),bytes.fromhex('9ac7cc9a609d1ef7b2932899cde41b975248c4959014126a6e8a84f11d1a9e1c')),
	(bytes.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718'),bytes.fromhex('0595e57fe5f0bb3c706edac8a4b2db11dfde31344a1af769c74f070aee9e2326')),
	(bytes.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),bytes.fromhex('eaa6bd25880bf93d3f5d1e4ca2611d91cfa45c9f7e714b54bdfa80027cb14380')),
	(bytes.fromhex('833222772a'),bytes.fromhex('80ad97bdc973df8a2e879e92a497efda20f060c2f2e5126501d3d4fea10d5fc0')),
	(bytes.fromhex('1910833222772a'),bytes.fromhex('bc9222dbd3274d8fc66d14ccbda6690b7ae627410c9a2be693df5bb7485a63e3')),
	(bytes.fromhex('641910833222772a'), bytes.fromhex('bbf609de9413172d07660cb68071692646101a6dab43115d6c522b4fe93604a9')),
	(bytes.fromhex('8b37641910833222772a'), bytes.fromhex('ab65c26eddb287600db2fda10d1e605cbb759010c29658f2c72d93a2d16d2930')),
	(bytes.fromhex('ebb46227c6cc8b37641910833222772a'), bytes.fromhex('720c94b63edf44e131d950ca211a5a30c366fdeacf9ca80436be7c358424d20b')),
	(bytes.fromhex('c109163908ebe51debb46227c6cc8b37641910833222772a'), bytes.fromhex('54b64e6b5a20b5e2ec84593dc7989da7c135eee237a85465ff97dc03924f45ce')),
	(bytes.fromhex('1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a'), bytes.fromhex('dd5bcb0018e922d494759d7c395d02d3c8446f8f77abf737685353eb89a1c9eb')),
]

#https://www.monkeybreadsoftware.net/example-encryption-aes-aestestvectors.shtml
aes_cbc_test_vectors = [
	#key, IV, input, output
	(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), bytes.fromhex('000102030405060708090A0B0C0D0E0F') , bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'), bytes.fromhex('7649abac8119b246cee98e9b12e9197d')),
	(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), bytes.fromhex('7649ABAC8119B246CEE98E9B12E9197D') , bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51'), bytes.fromhex('5086cb9b507219ee95db113a917678b2')),

]

aes_ecb_test_vectors = [
	#key, IV, input, output
	(bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'), None , bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'), bytes.fromhex('bd334f1d6e45f25ff712a214571fa5cc')),
	(bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'), None , bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51'), bytes.fromhex('974104846d0ad3ad7734ecb3ecee4eef')),
	(bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'), None , bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'), bytes.fromhex('f3eed1bdb5d2a03c064b5a7e3db181f8')),

]

#https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Des-64-64.test-vectors
des_ecb_test_vectors = [
	#key, IV, input, output
	(bytes.fromhex('8000000000000000'), None , bytes.fromhex('0000000000000000'), bytes.fromhex('95A8D72813DAA94D')),
	(bytes.fromhex('4000000000000000'), None , bytes.fromhex('0000000000000000'), bytes.fromhex('0EEC1487DD8C26D5')),
	(bytes.fromhex('2000000000000000'), None , bytes.fromhex('0000000000000000'), bytes.fromhex('7AD16FFB79C45926')),

]



ciphers = {
	'RC4' : {
				'modules' : ['cryptography','pyCrypto','pure'],
				'testvectors' : rc4_test_vectors,

	},
	'AES_ECB' : {
				'modules' : ['cryptography','pyCrypto','pure'],
				'testvectors' : aes_ecb_test_vectors,
	},
	'AES_CBC' : {
				'modules' : ['cryptography','pyCrypto','pure'],
				'testvectors' : aes_cbc_test_vectors,

	},
	'DES_ECB' : {
				'modules' : ['pyCrypto','pure'],
				'testvectors' : des_ecb_test_vectors,

	}


}




if __name__ == '__main__':
	print('Cipher wrapper test for symmetric cypto')

	for cipherName in ciphers:
		for moduleName in ciphers[cipherName]['modules']:
			cipherNameBase = cipherName
			if cipherName.find('_') != -1:
				cipherNameBase, mode = cipherName.split('_')

			print('Testing %s cipher from module %s' % (cipherName, moduleName))
			cipherObj = getSpecificCipher(cipherNameBase, moduleName)
			if cipherNameBase == 'RC4':
				for key, test_vector in ciphers[cipherName]['testvectors']:
					cipher = cipherObj(key)				
					assert test_vector == cipher.encrypt(b'\x00'*len(test_vector))
					print('\tTest vector passed with key: %s' % key.hex())
			
			elif cipherNameBase in ['AES','DES']:
				for key, IV, dataIn, dataOut in ciphers[cipherName]['testvectors']:
					if mode == 'ECB':
						cipher = cipherObj(key)
					elif mode == 'CBC':
						cipher = cipherObj(key, cipherMODE.CBC, IV = IV)
					assert dataOut == cipher.encrypt(dataIn)
					print('\tTest vector passed with key: %s' % key.hex())	


