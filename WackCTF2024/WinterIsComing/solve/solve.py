from pwn import *
from Crypto.Util.number import bytes_to_long
from hashlib import sha256
import unicodedata
import itertools

def multihash(m: bytes, s: int) -> bytes:
    for _ in range(0, s):
        m = sha256(m).digest()
    return m

def hash_split(m: bytes, s:int) -> list[int]:
    m = sha256(m).digest()
    m_bin = bin(bytes_to_long(m))[2:].rjust(256, "0")
    return [int(m_bin[i:i+s], 2) for i in range(0, 256, s)]

message_info = []
with open("WackAttack2024/WinterIsComing/solve/messages.txt", "r") as f:
    messages = f.readlines()
    for message in messages:
        data = bytes.fromhex(message.strip())
        message_len = bytes_to_long(data[:4])
        message = data[4:message_len+4]
        signature_info = data[message_len+4:]
        block_size = signature_info[0]
        message_hash = hash_split(message, block_size)
        message_info.append((message_hash, signature_info))

s = 'printflag'
possible_chars = [list(a) for a in zip(s.upper(), s.lower())]
possible_chars[0].append("ₚ")
possible_chars[3].append("ⁿ")
possible_chars[6].append("ₗ")
possible_chars[7].append("ₐ")

for possible_message in map(''.join, itertools.product(*possible_chars)):
    assert unicodedata.normalize('NFKC', possible_message).lower() == s
    possible_message = possible_message.encode()
    possible_message_hash_split = hash_split(possible_message, 16)
    for message_hash, signature_info in message_info:
        if all([mh <= fh for mh, fh in zip(message_hash, possible_message_hash_split)]):
            message_to_send = possible_message
            new_message_hash_to_use = possible_message_hash_split
            message_hash_to_use = message_hash
            signature_info_to_use = signature_info
            break

#pro = process(["python"]  + ["WackAttack2024/WinterIsComing/chal/program.py"])
pro = remote("ctf.wackattack.eu", 5015)
context.log_level = 'info'

diffs = [fh - mh for mh, fh in zip(message_hash_to_use, new_message_hash_to_use)]
signature = []
for i in range(0, 256//block_size):
    signature.append(signature_info_to_use[2:][(i*256//8):((i+1)*256//8)])
new_signature = []
for s,d in zip(signature, diffs):
    new_signature.append(multihash(s, d))

bin_message = hex(len(message_to_send))[2:].rjust(8, "0") + message_to_send.hex() + signature_info_to_use[:2].hex() + ''.join([ns.hex() for ns in new_signature])
r = pro.recvuntil(b"> ")
pro.sendline(bin_message.encode())
print(pro.recvuntil(b"> "))
