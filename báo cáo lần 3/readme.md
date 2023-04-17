# Basic privilege escalation in linux

> Báo cáo lần này chúng ta hoàn thành nốt leo quyền =))

## CRONJOBS

- Cronjobs (hay còn gọi là cron tasks) là một tính năng của hệ thống Linux cho phép người dùng lên lịch thực thi các tác vụ tự động vào các thời điểm nhất định.

### Khai thác

- Ở đây do trong file `/etc/crontab` có task tự động như sau
  ![image](https://user-images.githubusercontent.com/111769169/231814937-9f68e080-5582-4a3e-b4ed-343bd872e9c5.png)

- Tìm đường dẫn file `overwrite` bằng lệnh `find / -name "*overwrite.sh*"`

  ![image](https://user-images.githubusercontent.com/111769169/231818439-fc3353d7-f077-409c-bdc2-7b7b48f3c577.png)

- Khi ta kiểm tra các quyền của file `overwrite.sh`, ta thấy có quyền write
  ![image](https://user-images.githubusercontent.com/111769169/231818731-cc766a44-c68b-4fbf-9874-b220f8669bd8.png)

- Oke ta dùng vim hoặc nano để sửa file `overwrite.sh` thêm 2 dòng cuối
  ![image](https://user-images.githubusercontent.com/111769169/231825401-b470dd02-ef9c-43ba-9612-5f4bfd665374.png)

- Nếu đúng nó sẽ tương tự như trong hình
  ![image](https://user-images.githubusercontent.com/111769169/231825843-9008a79e-3624-4040-a70e-04cb87070ecc.png)
  ![image](https://user-images.githubusercontent.com/111769169/231826604-f88f1a19-4972-46c8-bfb4-ca059cd68dbb.png)

## Password Hunting
