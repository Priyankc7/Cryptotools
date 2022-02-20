'''
To do:
a. Create a 128-bit AES key, encrypt and decrypt each of the two files using AES in the CBC mode (AES implementations need to be based on hardware implementation of AES)
b. Repeat a using AES in the CTR mode
c. Repeat b with 256 bit key
d. Create a 2048-bit RSA key, encrypt and decrypt the files above with PKCS #1 v2 padding (at least v2.0, but use v2.2 if available; it may also be called OAEP). 
   This experiment can use a 1MB file for the second file size to reduce the runtime.
e. Repeat d with 3072 bit key
f. Compute a hash of each of the files using hash functions SHA-256, SHA-512, and SHA3-256
g. Create a 2048-bit DSA key, sign the two files and verify the corresponding signatures. If creating a key takes two parameters, use 224 bits for the exponent size. If the hash
   function algorithm needs to specified separately, use SHA-256.
h. Repeat part g with a 3072-bit DSA key (if the second parameter is required, use 256).

Additional Tasks to do:
Include simple checking of correctness of your code, namely, that computed ciphertexts decrypt to the original data and that signed messages properly verify.

Measuring execution times: 
make sure that you retrieve the times using sufficient precision (e.g., in microseconds or nanoseconds)

1. For a to e   (i)  measure time taken to generate a new key
                (ii) measure time taken to encrypt each of the files
                (iii)measure time it takes to decrypt each files and also compute
                (iv) encryption speed per byte for both files 
                (v)  decryption speed per byte for both files

2. For each hash function experiment listed in part (f), measure the total time to compute the hash of both files and compute per-byte timings.
3. For each signature experiment, measure (i)  the key generation time
                                          (ii) the time to produce a signature for both files
                                          (iii)the time to verify a signature on both of the files, and compute per-byte time for
                                          (iv) signing
                                          (v)  signature verification for both files
'''

import binascii
from cryptography.fernet import Fernet
import filecmp
import base64
import os 

def createsmallfile(filename):
   '''Creates small file'''
   f = open(filename,"wb")
   f.seek(1048576)
   f.write(b"\0")
   f.close()

def createlargefile(filename):
   '''Creates large file'''
   f = open(filename,"wb")
   f.seek(10485760)
   f.write(b"\0")
   f.close()

def comparefiles(file1,file2):
   '''Compares two files'''
   filecmp.clear_cache()
   print(filecmp.cmp(file1,file2,shallow=True))

def generatekey(keysize):
   '''
   Generates keys 
   16 bytes = 128 bit key
   32 bytes = 256 bit key

   '''
   # key = base64.urlsafe_b64encode(os.urandom(keysize))
   key = os.urandom(keysize)
   return key

if __name__=='__main__':
   smallfilename='smallfile.txt'
   largefilename='largefile.txt'

   # createsmallfile(smallfilename)
   # createsmallfile('smallfile1.txt')
   # createlargefile(largefilename)
   # comparefiles(smallfilename,'smallfile1.txt')
   key = generatekey(16)
   print(binascii.hexlify(key))

   os.stat("largefile.txt").st_size