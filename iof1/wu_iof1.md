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
* khi nhìn vào source code ta thấy được ```alloca(n*8)``` thì ta phát hiện ở đây là lỗi IOF, em sẽ lấy một ví dụ sau.

##### ví dụ
* thì theo lí thuyết trong clip, unsigned long int có phạm vi từ 0 đến 2 mũ 64 - 1  
![image](https://user-images.githubusercontent.com/111769169/222915627-394c9c91-bdb4-4ed8-b17e-2538354db457.png)  
