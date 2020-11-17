from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os
import binascii
from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key):
        self.key = md5(key).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data,AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)

    def AesEncrypt(msg, pwd):

        encrypted = AESCipher(pwd).encrypt(msg)
        return encrypted


""" Not ready yet"""

class RSA_Encrypt:

    def Encrypt(shellCode):

        keyPair = RSA.generate(2048, os.urandom)

        pubKey = keyPair.publickey()
        # print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
        pubKeyPEM = pubKey.exportKey()
        # print(pubKeyPEM.decode('ascii'))

        # print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
        # privKeyPEM = keyPair.exportKey()
        # print(privKeyPEM.decode('ascii'))
        num = len(shellCode)
        text = ''
        if num <= 400:
            array = [0x00] * 200
            num2 = num - 200
            array2 = [0x00] * num2
            for i in range(200):
                array[i] = shellCode[i]
            for j in range(num2):
                array2[j] = shellCode[200 + j]

            try:

                inArray = PKCS1_OAEP.new(pubKey).encrypt(bytearray(array))
                print(inArray)
                text = base64.b64encode(bytearray(inArray))
                inArray2 = PKCS1_OAEP.new(pubKey).encrypt(bytearray(array2))
                text = text, "|", base64.b64encode(bytearray(inArray2))
                print(text)
            finally:
                RSA.PersistKeyInCsp = False
        # if num > 400:
        #
        #     num3 = num - 400
        #     array3 = []
        #     array4 = []
        #     array5 = []
        #     for k in range(200):
        #         array3[k] = shellCode[k]
        #     for l in range(200):
        #         array4[l] = shellCode[200 + l]
        #     for m in range(num3):
        #         array5[m] = shellCode[400 + m]
        #     try:
        #         inArray3 = PKCS1_OAEP.new(pubKey).encrypt(array, True)
        #         text = base64.b64encode(inArray3)
        #         rSACryptoServiceProvider2.publicKey
        #         inArray4 = rSACryptoServiceProvider2.Encrypt(array4, True)
        #         text = text + "|" + base64.b64encode(inArray4)
        #         rSACryptoServiceProvider2.publicKey
        #         inArray5 = rSACryptoServiceProvider2.Encrypt(array5, True)
        #         text = text + "|" + base64.b64encode(inArray5)
        #     finally:
        #         rSACryptoServiceProvider2.PersistKeyInCsp = False
        return text