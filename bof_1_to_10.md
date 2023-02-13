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



