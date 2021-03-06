from Crypto.Cipher import AES
import base64
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = key

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