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
* ở đây chương trình cho ta nhập vào biến v6 8byte, khi thảo luận với các bạn khác và debug theo dõi chương trình thì ta thấy nhiệm vụ của chúng ta là không nên nhảy vào while và if.  
* hàm while điều kiện là ``` địa chỉ v6 so với giá trị địa chỉ v6 - (v3 & 0xFFFFFFFFFFFFF000)``` phải bằng nhau thì mới không chạy while nghĩa là giá trị ``` v3 & 0xFFFFFFFFFFFFF000 == 0``` khi lấy ``` 0xfff & 0xFFFFFFFFFFFFF000 ``` kết quả là 0 và 0x1000 thì kết quả 