import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sympy import sec

key = os.urandom(16)
# print(key)
iv = os.urandom(16)
# print(iv)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
# sec = b"a secret message"
sec = b"abcd"
length = 16 - (len(sec)%16)
print(length)
sec+= bytes([length])*length
print(sec)
ct = encryptor.update(sec) + encryptor.finalize()
print(ct)
decryptor = cipher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize()
print(pt)
print(length)
pt = pt[:-pt[-length]]
print(pt)