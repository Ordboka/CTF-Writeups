from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

g = 7
h = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
p = 4170887899225220949299992515778389605737976266979828742347

Rp = IntegerModRing(p)
g = Rp(g)
h = Rp(h)

fact = factor(p-1)

xs = []
mods = []

#Pohlig hellman for all but last factor
for f, _ in fact[:-1]:
    gi = g^(p//f)
    hi = h^(p//f)
    dl = discrete_log(hi,gi)
    xs.append(dl)
    mods.append(f)
 
x = crt(xs, mods)

tx = int(x)
ad = int(prod(mods))

ll = int((2^127-x)/(ad))
ul = int((2^128-x)/(ad))
h = int(h)

tx+=ll*ad
for i in range(ul-ll):
    tx+=ad
    if pow(7,tx,p) == h:
        key = tx
        break

ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")
print(AES.new(long_to_bytes(tx), AES.MODE_ECB).decrypt(ct))
