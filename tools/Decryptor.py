import argparse
import random
from Crypto.Cipher import AES
from pwn import *
from base64 import b64decode
import json

def decrypt(data, key, header):
    try:

        #b64 = json.loads(json_input)

        #json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]

        #jv = {k:b64decode(b64[k]) for k in json_k}

        cipher = AES.new(key, AES.MODE_GCM, nonce=data[32:48])

        cipher.update(header)

        plaintext = cipher.decrypt_and_verify(data[:16], data[16 : 32])

        print(plaintext)

    except (ValueError, KeyError):

        print("Incorrect decryption")
        
    return plaintext

firmware_blob = b""
# Load firmware binary from infile
with open("../firmware/gcc/protected.bin", 'rb') as fp:
    firmware_blob = fp.read()
#load secret key (256 bits) and header
key = b""
header = b""
#Reads secret_build_output.txt and parses it into the key (32 bytes) and the header (16 bytes)
with open ("../bootloader/secret_build_output.txt", "rb") as fp:
    key = fp.readline()
    key = key[0 : len(key) - 1]
    header = fp.readline()
    
#print(firmware_blob)

frame_1 = firmware_blob[:48]
f1d = decrypt(frame_1, key, header)#Frame 1 Decrypted

print(u8(f1d[0:1], endian = "big"))
print(u16(f1d[1:3], endian = "big"))
print(u16(f1d[3:5], endian = "big"))
print(u16(f1d[5:7], endian = "big"))