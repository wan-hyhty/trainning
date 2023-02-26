# IDA
Qua ida ta tóm tắt chương trình thực thi như sau  
* Nó tạo một random và chia đôi để bỏ vào biến buf và v6
* nó yêu cầu ta đoán giá trị sao cho bằng v6 + buf


```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int fd; // [rsp+Ch] [rbp-94h]
  __int64 buf; // [rsp+10h] [rbp-90h] BYREF
  __int64 v6; // [rsp+18h] [rbp-88h] BYREF
  __int64 v7[2]; // [rsp+20h] [rbp-80h] BYREF
  char format[104]; // [rsp+30h] [rbp-70h] BYREF
  unsigned __int64 v9; // [rsp+98h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  buf = 0LL;
  v6 = 0LL;
  fd = open("/dev/urandom", 0, envp);
  read(fd, &buf, 2uLL);
  read(fd, &v6, 2uLL);
  close(fd);
  puts("your name:");
  read(0, format, 0x64uLL);
  puts("you can guess a number,if you are lucky I will give you a gift:");
  v7[1] = (__int64)v7;
  __isoc99_scanf("%lld", v7);
  printf("hello ");
  printf(format);
  printf("let me see ...");
  if ( v6 + buf != v7[0] )
  {
    puts("you are not lucky enough");
    exit(0);
  }
  puts("you win, I will give you a shell!");
  system("/bin/sh");
  return 0;
}
```

___
# Định hướng
Sau khi được hint, ta có 2 hướng như sau:  
* Một là ta ow got@exit về hàm puts trước system nhưng lại bị xmm1  
* Hai là ta sẽ leak địa chỉ stack và tìm đến địa chỉ 2 biến v6 và buf và thay đổi giá trị mà ta muốn  
Vậy chỉ có các 2 là có thể thực hiện  
___
# Thực thi  
Vậy lần đầu tiên ta chạy hàm main ta phải leak được địa chỉ stack. Qua nhiều lần chạy, ta chú ý ở đây có địa chỉ stack, vậy là ta đã có được địa chỉ stack.  
![image](https://user-images.githubusercontent.com/111769169/221287354-4214cb92-3701-4a97-be94-975e8edff2d7.png)  

Đến lần chạy 2 ta chú ý địa chỉ stack này đã thay đổi  
![image](https://user-images.githubusercontent.com/111769169/221288566-8c102948-2567-4d4d-b6ee-9eb527047b8e.png)  
vậy ta thấy địa chỉ stack đã thay đổi, ta sẽ tìm địa chỉ off giữa địa chỉ leak được ở stack cũ và địa chỉ leak trong stack mới là ``` 0xb0 ```  
Đến đây ta sẽ tính các địa chỉ mới của biến v6 và biến buf, sau đó ghi giá trị của ta vào 2 biến đó, cuối cùng gửi giá trị đó dưới dạng decimal vì scanf có %lld  

# Lưu ý ta nên để %c%n lên đầu tiên payload, %n sẽ trỏ đến ***ĐỊA CHỈ*** và thay đổi giá trị tại địa chỉ đó  
