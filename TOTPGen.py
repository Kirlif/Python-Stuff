#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import sha1
from time import time
from sys import argv

'''
TOTPGen
January 2025

This piece of code to generate your TOTP passwords.
Works with any 2FA ;)

Usage:
~$ python3 TOTPGen.py key_name
where key_name is the name associated to the key in the KEYS dictionary.

~$ python3 TOTPGen.py
If no key_name is passed to the CLI "github" is used by default.
We can change this default setting. See below:
default_key = "github" # default key

Add your keys to the KEYS dictionary below like this:
"key_name": "key_value",
'''

KEYS = {
"github": "ABCDEFGHIJKLMNOP", # Base32 encoded secret key
}

default_key = "github" # default key

class TOTPGenerator:

    TIME_STEP = 30  # Time step in seconds
    DIGITS = 6      # Number of digits in the TOTP

    def __init__(self, key):
        self.secret = key
        self.time_index = int(time()) // self.TIME_STEP
        totp = self.generate_totp()
        print("TOTP:", totp)

    def generate_totp(self):
        key = self.decode_base32()
        time_bytes = self.time_index.to_bytes(8, byteorder='big')
        hash_value = self.compute_hmac(key, time_bytes)
        offset = hash_value[-1] & 0x0F
        binary = ((hash_value[offset] & 0x7F) << 24) | \
                 ((hash_value[offset + 1] & 0xFF) << 16) | \
                 ((hash_value[offset + 2] & 0xFF) << 8) | \
                 (hash_value[offset + 3] & 0xFF)
        otp = binary % (10 ** self.DIGITS)
        format_str = f"%0{self.DIGITS}d"
        return format_str % otp

    def decode_base32(self):
        binary_string = ""
        for c in self.secret:
            if 'A' <= c <= 'Z':
                i = ord(c) - ord('A')
            elif '2' <= c <= '7':
                i = ord(c) - ord('2') + 26
            else:
                raise ValueError(f"Invalid base32 char: '{c}'")
            binary_string += f"{i:05b}"
        byte_length = (len(binary_string) + 7) // 8
        bytes_array = bytearray(byte_length)
        for i in range(0, len(binary_string), 8):
            byte_string = binary_string[i:i + 8]
            bytes_array[i // 8] = int(byte_string, 2)
        return bytes(bytes_array)

    def compute_hmac(self, key, message):
        block_size = 64
        if len(key) > block_size:
            key = sha1(key).digest()
        padded_key = key.ljust(block_size, b'\0')
        inner_pad = bytes(b ^ 0x36 for b in padded_key)
        outer_pad = bytes(b ^ 0x5C for b in padded_key)
        inner_hash = sha1(inner_pad + message).digest()
        return sha1(outer_pad + inner_hash).digest()

if __name__ == "__main__":
    key_name = default_key
    if len(argv) == 2:
        key_name = argv[1] if argv[1] in KEYS else None
    if len(argv) <= 2 and key_name:
        TOTPGenerator(KEYS[key_name])
    elif not key_name:
        print("Key not found!")
