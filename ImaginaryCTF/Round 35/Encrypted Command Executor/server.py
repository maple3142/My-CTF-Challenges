from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from shlex import quote
from base64 import b64decode, b64encode
import os
from subprocess import Popen, PIPE, DEVNULL


def encrypt(key: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(ct, AES.block_size))


def decrypt(key: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ct), AES.block_size)


if __name__ == "__main__":
    print("=" * 40)
    print("Welcome to Encrypted Command Executor")
    print("=" * 40)
    key = os.urandom(AES.block_size)
    while True:
        print("1. Generate an echo command")
        print("2. Generate a ls command")
        print("3. Run an encrypted command")
        print("4. Exit")
        choice = input("> ")
        if choice == "1":
            msg = input("Message: ")
            cmd = "echo %s" % quote(msg)
            print("result:", b64encode(encrypt(key, cmd.encode())).decode())
        elif choice == "2":
            directory = input("Directory: ")
            cmd = "ls -- %s" % quote(directory)
            print("result:", b64encode(encrypt(key, cmd.encode())).decode())
        elif choice == "3":
            ct = input("Encrypted command: ")
            cmd = decrypt(key, b64decode(ct))
            proc = Popen(
                cmd.decode(), stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL, shell=True
            )
            stdout, _ = proc.communicate()
            print("result:", b64encode(encrypt(key, stdout)).decode())
        elif choice == "4":
            exit()
