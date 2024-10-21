#! /bin/python3

from Crypto.Util.number import bytes_to_long
import unicodedata
from flag import flag
from pubkey import public_key
from hashlib import sha256
import sys

def multihash(m: bytes, s: int) -> bytes:
    for _ in range(0, s):
        m = sha256(m).digest()
    return m

def hash_split(m: bytes, s:int) -> list[int]:
    m = sha256(m).digest()
    m_bin = bin(bytes_to_long(m))[2:].rjust(256, "0")
    return [int(m_bin[i:i+s], 2) for i in range(0, 256, s)]

def check_signature(data):
    message_len = bytes_to_long(data[:4])
    message = data[4:message_len+4]
    signature_info = data[message_len+4:]
    block_size = signature_info[0]
    signature_number = signature_info[1]
    signature  = [] 
    message_hash = hash_split(message, block_size)
    for i in range(0, 256//block_size):
        signature.append(signature_info[2:][(i*256//8):((i+1)*256//8)])
    if (len(public_key[signature_number]) != len(signature)):
        return False, b""
    for mh, pk, s in zip(message_hash, public_key[signature_number], signature):
        if multihash(s, 2**block_size-mh) != pk:
            return False, b""
    return True, message

if __name__ == "__main__":
    while True:
        inn = input("> ")

        inn = bytes.fromhex(inn)
        try:
            verified, message = check_signature(inn)
        except:
            print("Verification failed")
            sys.exit()

        if not verified:
            print("Verification failed")
            sys.exit()

        command = unicodedata.normalize('NFKC', message.decode()).lower()

        if command == "printflag":
            print(flag)
        elif command.split(" ")[0] == "echo":
            print(" ".join(command.split(" ")[1:]))
        elif command.split(" ")[0] == "exit":
            sys.exit()
        else:
            print(f"Command {command} not recognized")

