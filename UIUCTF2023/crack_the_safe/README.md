# crack_the_safe (Crypto 69 points)
**Keywords: Discrete log, Pohlig-Hellman, Smooth number**

## Understanding the task
The task is a very short and sweet one. We are given that there is a secret $key$ that has the following properties.

1. $7^{key}\equiv h\mod p$ for a given $h$ and $p$
2. `AES.new(key, AES.MODE_ECB).decrypt(ct) == FLAG` where `ct` is given

This is all we get, but from this I saw that we were dealing with the discrete log problem. Because if I can find out what $key$ is I can decrypt the `ct` and get the `FLAG`.

## Solving discrete log
Now that I knew what the problem was I tried to just use SageMath to solve the dlog problem for me with the built in dlog method.

```
g = 7
h = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
p = 4170887899225220949299992515778389605737976266979828742347

Rp = IntegerModRing(p)
g = Rp(g)
h = Rp(h)
dl = discrete_log(h,g)
```

After waiting for a few minutes to finally have the process killed for consuming too much memory I figured the problem was a bit more complicated and I would have to come up with something smarter. 

After the CTF I learned that if you instead were to use [CADO-NFS](https://cado-nfs.gitlabpages.inria.fr/) you could actually just solve the dlog without any more trouble. I did actually try to install [CADO-NFS](https://cado-nfs.gitlabpages.inria.fr/) during the CTF but couldn't get it to work since the official site was down and the GitHub fork wouldn't successfully build on my machine.

## Pohlig-Hellman

My next idea was to check the factors of $p-1$ since if $p-1$ has small factors we can use the Pohlig-Hellman algorithm to find an $a$ satisfying $a\equiv key \mod f$ for some factor $f$. Using the Chinese remainder theorem we could then combine these factors and get $b\equiv key \mod \prod f_i$ where $\prod f_i $ divides $p-1$.

Factoring $p-1$ gives us $p-1 = 2 * 19 * 151 * 577 * 67061 * 18279232319 * 111543376699 * 9213409941746658353293481$. Looking at the factors they don't seem too big, so I went and implemented the Pohlig-Hellman algorithm as described on [Wikipedia](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm#The_general_algorithm).


```
g = 7
h = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
p = 4170887899225220949299992515778389605737976266979828742347

Rp = IntegerModRing(p)
g = Rp(g)
h = Rp(h)

fact = factor(p-1)

xs = []
mods = []

for f, _ in fact:
    gi = g^(p//f)
    hi = h^(p//f)
    dl = discrete_log(hi,gi)
    xs.append(dl)
    mods.append(f)
 
x = crt(xs, mods)
```

Sadly, this also didn't work. The `discrete_log` function in SageMath actually uses Pohlig-Hellman, so this is not really a surprise. However, if I instead only focus on all but the last factor of $p-1$ it successfully finds an answer. Of course this answer $x$ is just $key\equiv x \mod \prod f_j$ where $\prod f_j = \frac{p}{f_l} $ where $f_l$ is the last factor.

## AES Key

I was stuck at this point for a while until I remembered one important detail from the problem. $key$ is used as a key for encrypting with AES and AES requires that the key is either 128, 192 or 256 bits. Since $p$ is 192 bits we only have to check for 128 and 192 bit possibilities. Because we know that $key\equiv x \mod \prod f_j$ we can rewrite this to be $key = x  +  q\prod f_j$ for some $q$. If $key$ is 192 bits this doesn't actually restrict $q$ much, but if we instead cross our finger ans hope that $key$ is instead 128 bits then $q$ is restricted to be $(\frac{2^{127}-x}{\prod f_j} = 375837) < q < (\frac{2^{128}-x}{\prod f_j} = 751676)$. This is a very manageable range to brute force by for each value of $q$ checking if $7^{x  +  q\prod f_j}\equiv h\mod p$ This is what I did and luckily for me $key$ was 128 bits and when $q = 446037$ the equivalence was fulfilled. I now knew that is $key = x  +  446037\prod f_j$. How the search was done is shown below.

```
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
```

## Finishing up

With the knowledge of the value of $key$ all that was left to do was to decrypt the `ct` with the $key$.

```
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")
print(AES.new(long_to_bytes(tx), AES.MODE_ECB).decrypt(ct))
```

This finally gave us the `FLAG` **uiuctf{Dl0g_w/__UnS4F3__pR1Me5_}**

## Conclusion and full code

I have to admit I was very lucky that the authors of the challenge did not choose a 192 bit key. For next time I will definitely use [CADO-NFS](https://cado-nfs.gitlabpages.inria.fr/) now that I know how powerful it can be. Nevertheless, I learnt more about the Pohlig-Hellman and had fun!

```
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
```