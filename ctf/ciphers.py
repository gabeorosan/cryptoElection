from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import os
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = key
        #b'\xf7&\\d\x7f\x04\xbe\x0b\x19\xf0\xfd\x15\x83K\x9d}'

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = b'\0'*16 #Default zero based bytes[16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(raw.encode()))
    def decrypt(self, raw):
        raw = base64.b64decode(raw)
        iv = b'\0'*16 #Default zero based bytes[16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(raw)

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)