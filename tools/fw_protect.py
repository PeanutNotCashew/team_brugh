#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
import ser, run_lab, lab_backends
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from pwn import *

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)

""" 
1. Pads data into chunks
2. Generates hashes using  SHA-256
    a. Create temporary copy of chunk, to remember which chunk caused an error
3. Encrypts those chunks and hashes into AES-256-GCM 

"""

def temp_copy(padded_chunk_for_sha):
    storage = []
    copied_temp = padded_chunk_for_sha 
    storage.append(copied_temp)
    return storage

def SHA_generator():
    padded_chunk_for_sha = '' 
    h = SHA256.new(padded_chunk_for_sha)
    h.update(padded_chunk_for_sha)
    ser.write(padded_chunk_for_sha)
    return padded_chunk_for_sha