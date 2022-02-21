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


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import filecmp
import os 
import time
import base64
import binascii


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
   if (filecmp.cmp(file1,file2,shallow=True)):
      print(f'The files {file1} and {file2} are verified!\n\n')
   # print(filecmp.cmp(file1,file2,shallow=True))

def generatekey(keysize):
   '''
   Generates keys 
   16 bytes = 128 bit key
   32 bytes = 256 bit key

   '''
   # key = base64.urlsafe_b64encode(os.urandom(keysize))
   key = os.urandom(keysize)
   return key

def AES_CBC(key,inputFile,outputfile):
   '''Encrypts the file using AES_CBC mode'''
   ##Opening the file and loading the original contents
   with open(inputFile, 'rb') as file:
      original = file.read()
      length = 16 - (len(original)%16)
      original += bytes([length])*length
      file.close()

   ##Generating IV and encrypting the file contents
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
   encryptor = cipher.encryptor()
   ct = encryptor.update(original) + encryptor.finalize()
 
   ##Writing the encrypted contents into the file
   with open(outputfile, 'wb') as file:   
      file.write(ct)
      file.close()
   print(f"The file {inputFile} has been encrypted and contents stored to {outputfile}")

   ##Opening the file and loading the encrypted contents
   with open(outputfile, 'rb') as file:
      encrypted = file.read()
      file.close()

   ##Decrypting the file contents
   decryptor = cipher.decryptor()
   pt = decryptor.update(encrypted) + decryptor.finalize()
   pt = pt[:-pt[-length]]
 
   ##Writing the decrypted file contents into the file
   with open(outputfile,'wb') as file:
      file.write(pt)
      file.close()
   print(f"The file {outputfile} has been decrypted")


def AES_CTR(key,inputFile,outputfile):
   '''Encrypts the file using AES_CTR mode'''
   ##Opening the file and loading the original contents
   with open(inputFile, 'rb') as file:
      original = file.read()
      # length = 16 - (len(original)%16)
      # original += bytes([length])*length
      file.close()

   ##Generating IV and encrypting the file contents
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key),modes.CTR(iv))
   encryptor = cipher.encryptor()
   ct = encryptor.update(original) + encryptor.finalize()
 
   ##Writing the encrypted contents into the file
   with open(outputfile, 'wb') as file:   
      file.write(ct)
      file.close()
   print(f"The file {inputFile} has been encrypted and contents stored to {outputfile}")

   ##Opening the file and loading the encrypted contents
   with open(outputfile, 'rb') as file:
      encrypted = file.read()
      file.close()

   ##Decrypting the file contents
   decryptor = cipher.decryptor()
   pt = decryptor.update(encrypted) + decryptor.finalize()
   # pt = pt[:-pt[-length]]
 
   ##Writing the decrypted file contents into the file
   with open(outputfile,'wb') as file:
      file.write(pt)
      file.close()
   print(f"The file {outputfile} has been decrypted")


if __name__=='__main__':
   smallfile='smallfile.txt'
   newsmallfile = 'newsmallfile.txt'
   largefile='largefile.txt'
   newlargefile='newlargefile.txt'

   createsmallfile(smallfile)
   # createsmallfile('smallfile1.txt')
   createlargefile(largefile)
   # comparefiles(smallfilename,'smallfile1.txt')
   
   '''''''''''''''''
   Task a
   '''''''''''''''''
   key = generatekey(16)
   print(f'The key is : {binascii.hexlify(key)}') #string is prefixed with the ‘b,’ which says that it produces byte data type instead of the string data type

   
   start_time = time.time()
   AES_CBC(key,smallfile,newsmallfile)
   print("--- %s seconds AES CBC 1MB ---" % (time.time() - start_time))   
   comparefiles(smallfile,newsmallfile)

   start_time = time.time()
   AES_CBC(key,largefile,newlargefile)
   print("--- %s seconds AES CBC 10MB ---" % (time.time() - start_time))
   comparefiles(largefile,newlargefile)

   '''''''''''''''''
   Task b
   '''''''''''''''''

   start_time = time.time()
   AES_CTR(key,smallfile,newsmallfile)
   print("--- %s seconds AES CTR 1MB ---" % (time.time() - start_time))
   comparefiles(smallfile,newsmallfile)

   start_time = time.time()
   AES_CTR(key,largefile,newlargefile)
   print("--- %s seconds AES CTR 10MB ---" % (time.time() - start_time))
   comparefiles(largefile,newlargefile)


   '''''''''''''''''
   Task c
   '''''''''''''''''
   key = generatekey(32)
   print(f'The key is : {binascii.hexlify(key)}') #string is prefixed with the ‘b,’ which says that it produces byte data type instead of the string data type

   start_time = time.time()
   AES_CTR(key,smallfile,newsmallfile)
   print("--- %s seconds AES CTR 1MB ---" % (time.time() - start_time))
   comparefiles(smallfile,newsmallfile)

   start_time = time.time()
   AES_CTR(key,largefile,newlargefile)
   print("--- %s seconds AES CTR 10MB ---" % (time.time() - start_time))
   comparefiles(largefile,newlargefile)


   # os.stat("largefile.txt").st_size