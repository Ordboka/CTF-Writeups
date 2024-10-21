# Winter is coming (Crypto 500 points)
**Keywords: Hash, Winternitz One Time Signature Scheme**

## Understanding the task
Looking at the [program.py](chal/program.py) script we can see a program that takes a message from the user, verifies that it is a message that has been properly signed, and then if it is executes the command given in the message. The goal for us is to send the server a message that will make it execute the command printflag.

In addition to [program.py](chal/program.py) we are also given [pubkey.py](chal/pubkey.py) which contains 200 different public keys. Each public key consists of a list of 16 256 bit values.

Finally we are given [mim.pcap](chal/mim.pcap) which consists of some random internet traffic, but mostly communication between a client and a server where the client sends a lot of valid messages to the server all being echo commands. 71 messages back and forth in total.

## Understanding the signature scheme

This was a signature schema I at least had never seen before so the first thing I needed to do was to understand it (I have later been told it is the [Winternitz One Time Signature Scheme](https://sphere10.com/articles/cryptography/pqc/wots) with checksums missing). The basics of it is that the messages is hashed with SHA256, divided into 16 blocks, each becoming a 16 bit integer. The client provides 16 256 bit values. Then the server to verify the message takes the 16 16 bit integers ($mh$) from the message, the 16 256 bit values from the public key indicated by the message to use ($pk$), and the 16 256 bit values of the signature ($s$). For each of these 16 it checks that if the signature is hashed $2^{16}-mh$ times it equals $pk$. If this is true for all 16 the message is considered valid.

After understanding how the validation worked I had to try to figure out how the signatures was created. As hashing functions are famously a one way function I knew that it would not be possible for the creators of the signature to work backwards from the public key. Instead I had to figure out what the private key was, in relation to the public key. What I figured out is that the private key is probably just 16 random values, but that the public key are these values all hashed $2^{16}$ times. This way when the client wants to create a signature it hash the private key $mh$ times and get the signature it needs.

## Breaking the signature scheme

Since we were given 71 valid messages with signatures the question now is how can we use these to break the signature scheme. For each message we know both the message, so we can calculate the $mh$ values, and the signature $s$ values. The trick now is to notice that if we hash one of the signatures one more time, it will be valid for a message that has $mh_{new}$ = $mh_{old} + 1$. Therefore, if one of the messages we have received has all 16 $mh$ values lower than the message we want to send, we can use the signature of that message to sign our own message, by hashing all the signatures $mh_{old}-mh_{new}$ times. 

## Solving the task

With a plan for solving the task, the only thing that is left is to implement it. The first thing I needed to do was to get all the messages sent from the pcap. For someone who pretty much exclusively does crypto task, I feared this would be some work, but luckily with wireshark it was very easy. I simply opened the pcap, clicked follow on one of the TCP streams, and then in the new window switched from "Entire conversation" to only the "Client to server" messages. I could then copy paste the messages into a file that made it very easy to work with in python.

After parsing every message I could then try to find if any of them had all 16 $mh$ values lower than the message "printflag". However, this proved not to be the case, not too surprising seeing as this would only happen once in every $2^{16}$ messages. Luckily I had noticed the strange line

```python
command = unicodedata.normalize('NFKC', message.decode()).lower()
```

in the code earlier. Why would this be needed when the client was only sending normal lower case ascii characters? The answer is to give us more messages to try with. I therefore first tried with all $2^{len("printflag")}$ variation of upper and lower case versions of printflag, but even this did not give me a successful result. I therefore had to read up on [Unicode normalization](https://en.wikipedia.org/wiki/Unicode_equivalence#Normalization). What I then realised is that with the "NFKC" normalization characters that are similar to ascii characters would often be converted to the ascii character. For example I found out that the subscript and superscript versions of the characters would be converted to the normal ascii character. This gave me a lot more options, and after manually adding a few of these subscript and superscript characters to the list of options for each character I finally found a message that had all 16 $mh$ values higher than one of the messages we had received. All that was left was crafting the message and sending it to the server.

The final solve script can be found in [solve.py](solve/solve.py)