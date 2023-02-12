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
