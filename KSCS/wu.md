# Cat
Đầu tiên ta đọc ida thì chương trình nhập user và pass  
dòng 16 thì so sánh user nhập vào với 'KCSC_4dm1n1str4t0r',  
![image](https://user-images.githubusercontent.com/111769169/218703859-3bb5da40-4884-4bca-9781-bfcb29534857.png)  
và pass với cái gì đó nên ta đổi sang asm  
thì thấy so sánh với 'wh3r3_1s_th3_fl4g'  
![image](https://user-images.githubusercontent.com/111769169/218703964-427cc7ca-9cba-4e04-9e49-a6081952d460.png)  
tiếp đến chương trình nhập vào 512 kí tự và rồi in ra  
tuy nhiên ở đây ta thấy read() chỉ đọc 512 vào không có byte null kết thúc chuỗi nên khi ta nhập đủ 512byte, khi in ra chuỗi vừa nhập sẽ nối với flag  
![image](https://user-images.githubusercontent.com/111769169/218704309-87c3547e-094f-4755-a25e-597f3ef182ab.png)  

# Treasure
Khi chạy, chương trình in ra "Part 1: KCSC{"   
  part 2 trong file có 4_t1ny_tr34sur3  
![image](https://user-images.githubusercontent.com/111769169/218707107-5bf79c9b-da19-4b24-9b74-0f88906b4332.png)  
  Part 3:  
  ![image](https://user-images.githubusercontent.com/111769169/218707541-b041dfa3-0ecf-4c9f-9734-1816f22a3d41.png)
  
# overthewrite
Nhiệm vụ của ta là làm thay đổi các biến để thoả 4 điều kiện  

tìm offset  
stage 1: 76byte  
stage 2: 64byte  
stage 3: 56byte  
stage 4: 32byte  
file: [overthewrite](https://github.com/wan-hyhty/trainning/blob/task-1/KSCS/file/overthewrite)  
![image](https://user-images.githubusercontent.com/111769169/218717303-9afd0f9a-3084-47a0-83f8-dc6389188278.png)  
[overthewrite.py](https://github.com/wan-hyhty/trainning/blob/task-1/KSCS/file/overthewrite.py)  
