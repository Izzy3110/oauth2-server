import base64
import os.path
from io import BytesIO

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class SecurityManager(object):
    key = None
    key_file = "key.bin"

    @staticmethod
    def generate_salt():
        return get_random_bytes(32)

    @staticmethod
    def generate_key(key_password=None):
        salt = SecurityManager.generate_salt()
        password = 'password123' if key_password is None else key_password
        key = PBKDF2(password, salt, dkLen=32)
        with open(SecurityManager.key_file+".tmp", "wb") as key_file:
            key_file.write(key)
            key_file.close()
        return key

    def setup_key(self, key_file=None, return_=None):
        if key_file is not None:
            self.key_file = key_file
        if os.path.isfile(self.key_file):
            with open(self.key_file, "rb") as key_f:
                key = key_f.read()
                if len(key) > 0:
                    self.key = key
                    if return_ is not None and return_:
                        return self.key
        else:
            print("no keyfile")

    def encrypt_password(self, password):
        if self.key is not None:
            cipher = AES.new(self.key, AES.MODE_CBC)
            return base64.b64encode(b''.join([cipher.iv, cipher.encrypt(
                pad(password.encode("utf-8"), AES.block_size)
            )])).decode()
        else:
            self.setup_key()
            super(self.encrypt_password(password))

    def decrypt_password(self, password_encrypted):
        b64_decoded = base64.b64decode(password_encrypted.encode())
        bio = BytesIO(b64_decoded)
        iv = bio.read(16)
        data = bio.read()
        bio.close()
        return unpad(AES.new(open(self.key_file, "rb").read(), AES.MODE_CBC, iv=iv).decrypt(data),
                     AES.block_size).decode("utf-8")
