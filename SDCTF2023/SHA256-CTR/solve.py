from hashpumpy import hashpump
from Crypto.Util.number import long_to_bytes
from pwn import *

#p = process(["python"]  + ["SDCTF2023/SHA256-CTR/sha256ctr.py"])
p = remote("shactr.sdc.tf", 1337)

n_blocks_in_flag = 2

# Get hashes of counter
hashes = []
for i in range(n_blocks_in_flag):
    p.recvuntil(b">")
    p.sendline(b"2")
    p.recvuntil(b":")
    p.sendline(b"0"*64) #To get the xor of 0 and the hash
    hashes.append(p.recvuntil(b"Menu").decode().splitlines()[-2].split()[-1])

# Increase counter
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"=")
p.sendline(str(2**263+2**496+2**512-n_blocks_in_flag).encode())

# Get flag encrypted with the hash we can figure out
p.recvuntil(b">")
p.sendline(b"1")
encrypted_flag = p.recvuntil(b"Menu").decode().splitlines()[-2].split()[-1]
print(encrypted_flag)

# Perform hash extension hack to figure out key
key = ""
for i in range(n_blocks_in_flag):
    o = "a" #Just a random value
    data_to_add = chr(1)
    key_length = 31
    key += hashpump(hashes[i],o,data_to_add, key_length)[0]
# Make key same length as flag
key = key[:len(encrypted_flag)]
decrypted_flag = long_to_bytes(int(key,16)^int(encrypted_flag,16))
print(decrypted_flag.decode())