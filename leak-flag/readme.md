# khai thác
ở đây ta thấy lỗi FMT
```c
    puts("Here's a story - ");
    printf(format);
```
và flag nó được lưu trong stack nên ta có thể dùng %p để leak flag ra
do là file 32bit nên ta sẽ đếm từ đầu stack đến flag là 36

vậy ta leak đến khi ra hết chuỗi và có thể dùng cyberchef để đổi hex sang ascii
![image](https://user-images.githubusercontent.com/111769169/224525080-bc689855-b265-4cbf-a83f-ec5e201609d7.png)
