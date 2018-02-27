from responder3.crypto.DES import *
from passlib.hash import lmhash

#impacket
def __expand_DES_key( key):
        # Expand the key from a 7-byte password key into a 8-byte DES key
        key  = key[:7]
        key += b'\x00'*(7-len(key))
        s  = (((key[0] >> 1) & 0x7f) << 1).to_bytes(1, byteorder = 'big')
        s += (((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1).to_bytes(1, byteorder = 'big')
        s += (((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1).to_bytes(1, byteorder = 'big')
        s += (((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1).to_bytes(1, byteorder = 'big')
        s += (((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1).to_bytes(1, byteorder = 'big')
        s += (((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1).to_bytes(1, byteorder = 'big')
        s += (((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1).to_bytes(1, byteorder = 'big')
        s += ( (key[6] & 0x7f) << 1).to_bytes(1, byteorder = 'big')
        return s

LM_SECRET = b'KGS!@#$%'

#LMhash=DESeach(DOSCHARSET(UPPERCASE(password)), "KGS!@#$%")

secret = 'PASSWORD'

pl_hash = lmhash.hash(secret)


t1 = secret[:14].ljust(14, '\x00').upper()
print(t1)
p1 = t1[:7].encode('ascii')
print(p1)
p2 = t1[7:].encode('ascii')
print(p2)

d = des(__expand_DES_key(p1))
r1 = d.encrypt(LM_SECRET)
d = des(__expand_DES_key(p2))
r2 = d.encrypt(LM_SECRET)

lm_hash = r1+r2
print(lm_hash.hex()) 
print(pl_hash)