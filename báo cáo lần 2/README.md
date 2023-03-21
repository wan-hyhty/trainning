# Linux Privilege Escalation
## Một số bước cần thực hiện 

- Để có thể vừa học lí thuyết vừa có thể thực hành ta cần chuẩn bị một số thứ sau
  - Đầu tiên cần có 2 ubuntu, bản 20.04 và 20.05 hoặc các bản tương ứng ([20.05](https://www.microsoft.com/store/productId/9MTTCL66CPXJ) [20.04](https://www.microsoft.com/store/productId/9PN20MSR04DW))
  - Ở đây em chọn bản 20.05 là bản tạo server
### setup server
- Đầu tiên, ở bản 20.05 ta sẽ chạy câu lện sau
```sudo apt-get install openssh-server```  
![image](https://user-images.githubusercontent.com/111769169/226509561-dc21236a-ead2-49ea-a8af-1b6a8a80420d.png)  
- tiếp đên câu lệnh ```sudo service ssh status```  
![image](https://user-images.githubusercontent.com/111769169/226509656-db7afd86-681e-4dbe-972f-c197defe34d4.png)  
- Nếu nó đã ``` * sshd is running ``` thì ta sẽ ```ssh localhost```
- tiếp đến ta chạy câu lệnh ```sudo nano /etc/ssh/sshd_config```, ta sửa lại như hình  
![image](https://user-images.githubusercontent.com/111769169/226510123-1b143bee-bdf3-4262-8eec-aef8096fc33c.png)  
![image](https://user-images.githubusercontent.com/111769169/226510582-7c24f117-ba01-4697-889a-463bbfc5479c.png)  
