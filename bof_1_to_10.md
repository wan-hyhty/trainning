# Tràn biến 1  
file: [bof1](https://github.com/wan-hyhty/trainning/blob/task-1/bof1)  
Mục tiêu thoả mãn điều kiện if để thực thi hàm system  
![image](https://user-images.githubusercontent.com/111769169/218325211-d41a3607-19b0-4012-b19e-f836caf09ca0.png)  
   
Qua ida em thấy có buf[16] nhưng được read đến 48 kí tự  
![image](https://user-images.githubusercontent.com/111769169/218325058-17acbc96-f7d0-499e-83b9-84562322136a.png)  
Vậy xuất hiện lỗi BOF.  
Em kiểm tra offset của biến a,b,c thì thấy từ kí tự thứ 17 thì có thể thay đổi các biến a, b,c nhằm thoả điều kiện khác 0  
![image](https://user-images.githubusercontent.com/111769169/218325995-9102a556-f18c-497e-86ef-206d1f29c76c.png)  
   
   
   
# Tràn biến 2  
file: [bof2](https://github.com/wan-hyhty/trainning/blob/task-1/bof2)  
Mục tiêu đổi giá trị các biến a, b, c sao cho thoả điều kiện sau   
![image](https://user-images.githubusercontent.com/111769169/218327149-d49ab298-6e9b-4e76-abde-0053a8aba3b9.png)  
Em tìm offset các biến a, b, c  
![image](https://user-images.githubusercontent.com/111769169/218327242-8f466caa-fb24-46ef-b1c6-56c14b6f2d4d.png)  
Cuối cùng,  
![image](https://user-images.githubusercontent.com/111769169/218327686-2d459d1b-817e-4a0c-9e52-42edd6b8b23f.png)   
code: [bof2.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof2.py)  
  
  
# Ret2win
![image](https://user-images.githubusercontent.com/111769169/218328023-c8bb1666-93c8-466f-8e19-ade44d943f29.png)  
Nhiệm vụ là thay đổi địa chỉ thanh rip đang trỏ đến.  
  
file: [bof3](https://github.com/wan-hyhty/trainning/blob/task-1/bof3)  
Mục tiêu là BOF đến thanh rip sau đó truyền địa chỉ hàm win  
Lưu ý khi truyền địa chỉ win tránh nhảy vào đầu hàm có thể gây lỗi  
Em tìm offset của rip = 40, tiếp theo ta sẽ truyền địa chỉ hàm win  
Đến đây ta có 2 trường hợp, 1 là địa chỉ tĩnh và 2 là trường hợp địa chỉ động  
### TH 1: địa chỉ tĩnh  
ta tìm địa chỉ hàm win bằng cách print địa chỉ win  
![image](https://user-images.githubusercontent.com/111769169/218329010-433f6602-a022-43e2-95f4-76d2a83eabc7.png)  
tiếp đến viết script  
![image](https://user-images.githubusercontent.com/111769169/218329482-19c4caf8-c760-4297-8cac-2413a2c5bde0.png)  
***Lưu ý*** nên tránh việc nhảy vào đầu hàm sẽ gây ra lỗi xmm1...(stack không chia hết cho 16), tốt nhất nên nhảy vào địa chỉ sau lệnh push đầu hàm  
code: *[bof3.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof3.py)*
#
### TH2: địa chỉ động
script:  
![image](https://user-images.githubusercontent.com/111769169/218329754-7ea621f1-e247-4a90-8ef3-c02c00b259f7.png)  
code: [bof3.2.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof3.2.py)  
   
   
   
# ROPgadget  
file: [bof4](https://github.com/wan-hyhty/trainning/blob/task-1/bof4)
Mục đích: thực hiện hàm execve("/bin/sh", 0, 0)  
   
đầu tiên ta dùng ROPgadget --binary <tên file>
ta sẽ tìm pop rdi (arg[1]), pop rsi (arg[2]), pop rdx (arg[3]), rax  
   
Trước hết ta sẽ kiểm tra chuỗi /bin/sh có sẵn ch, nếu có chuyển sang bước tiếp theo  
Nếu không ta phải truyền chuỗi /bin/sh vào bằng cách gọi hàm gets nhưng tham số lưu chuỗi nhập vào ở địa chỉ trống cố định trước đó.  
![image](https://user-images.githubusercontent.com/111769169/218334543-04f98a5b-25ad-4988-9193-41552663902b.png)  
   
Sau đó, thực thi hàm execve, do hàm execve có 3 tham số nên ta sẽ setup thanh rdi (truyền địa chỉ con trỏ lưu chuỗi), rsi, rdx, và rax = 0x3b  
   
![image](https://user-images.githubusercontent.com/111769169/218334648-7b13bd5e-6288-4c44-89c5-8345294b5f59.png)  

code: [bof4.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof4.py)
   
   
# Ret2shellcode không leak
file: [bof5](https://github.com/wan-hyhty/trainning/blob/task-1/bof5)  
khi NX tắt ta có thể thực thi stack
Nhiệm vụ: đưa shellcode vào trong stack, dùng thanh ghi để thực hiện shell (call hoặc jmp)  
![image](https://user-images.githubusercontent.com/111769169/218352948-b9f78154-8136-4dad-8d37-587ff5df3645.png)  
shellcode có thể tìm trên mạng tuỳ theo file 64 hay 32bit, hoặc có thể dùng asm  
tiếp đến ta sẽ BOF đến địa chỉ saved rip và truyền địa chỉ call_rax để chương trình nhảy vào rax và thực thi shell  
script: [bof5.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof5.py)  
   
# ret2shellcode leak
để có thể thì ta cần tìm mội lỗi fmt, ví dụ read nhưng không thêm byte null cuối chuỗi để leak được địa chỉ trong stack
sau đó, ta sẽ đưa shellcode vào trong stack, tuỳ trường hợp ta sẽ tìm offset từ địa chỉ ta leak được đến địa chỉ rip trỏ, sau đó set rip về địa chỉ shellcode - offset  
file [bof6](https://github.com/wan-hyhty/trainning/blob/task-1/bof6)  
script [bof6.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof6.py)

# ret2libc
GOT: nơi chứa địa chỉ các hàm của libc  
PLT: thực thi hàm được chứa trong GOT  
0x403fd8 <puts@got.plt>:	0x00007fffff7e49420  
0x403fd8 là GOT chứa địa chỉ 0x00007fffff7e49420 và PLT thực hiện địa chỉ đó  
Nhiệm vụ là setup thanh ghi rdi thành địa chỉ puts để leak địa chỉ libc  
do libc ở local khác với libc ở server, lưu ý ở mỗi libc sẽ có 3 giá trị cuối của địa chỉ leak là giống nhau  
Để tìm file libc ta sử dụng trang libc.rip (libc.blukat.me), ô đầu là hàm ô thứ 2 là địa chỉ của hàm  
Sau đó sử dụng công cụ pwninit  
Tiếp đến ta tìm địa chỉ base, là địa chỉ nhỏ nhất của file mà ta load lên  
địa chỉ base = địa chỉ đã leak - địa chỉ hàm (puts) trong libc  
  
tạo shellcode  
đầu tiên ta cần kiểm tra chuỗi /bin/sh đã tồn tại ch, nếu chưa ta phải gọi hàm gets để truyền chuỗi vào  
nếu rồi ta sẽ set thanh ghi rdi + địa chỉ chuỗi /bin/sh rồi truyền địa chỉ hàm system  

![image](https://user-images.githubusercontent.com/111769169/218503278-3696b7ca-eca6-4560-ae41-dc6883d54059.png)  
file: [bof7](https://github.com/wan-hyhty/trainning/blob/task-1/bof7)  
libc : [mẫu chạy local](https://github.com/wan-hyhty/trainning/blob/task-1/libc6-amd64_2.31-0ubuntu9.1_i386.so)  
file [bof7_patched](https://github.com/wan-hyhty/trainning/blob/task-1/bof7_patched)  
code: [bof7.res](https://github.com/wan-hyhty/trainning/blob/task-1/bof7.py)  

# saved rbp để chuyển hướng luồng thực thi  
overwrite thanh ghi saved $rbp để chuyển hướng luồng thực thi  
là khi overwrite nhưng không đến $rip chỉ làm thay đổi thanh RBP  
tìm offset của thanh rbp  
tìm địa chỉ mà có quyền wr (có thể trong stack)  
nếu trong stack thì ta cần truyền địa chỉ hàm win vào payload của mình (nên payload chỉ toàn địa chỉ hàm win để dễ dàng khi return vào stack)  
lưu ý lệnh leave và return, khi leave thực hiện thì stack + thêm 8byte, return thực hiện thì stack + 8byte)  
Các bài tương tự:
file [msnw](https://github.com/wan-hyhty/dreamhack/blob/main/MSMW/msnw)  
[saved rbp vào payload chứa địa chỉ win](https://github.com/wan-hyhty/dreamhack/blob/main/MSMW/res.py)  

   
Cần lưu ý những vị trí [rpb - 0x20...], vì khi thực hiện xong hàm con (hàm khác trong hàm main), địa chỉ rbp sẽ trừ đi và thực hiện tại địa chỉ mới  
nên nếu muốn trỏ vào vị trí stack ta cần + thêm để khi trừ đi rbp sẽ đúng bằng địa chỉ ta muốn  
[bof9.py](https://github.com/wan-hyhty/trainning/blob/task-1/bof9.py)

file [bof9]()  
