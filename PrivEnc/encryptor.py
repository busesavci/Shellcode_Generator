from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

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